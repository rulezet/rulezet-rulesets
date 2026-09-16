rule TTP_XOR_WriteProcessMemory_f305 {
  strings:
    $key_f305 = { a4 77 [2] 96 55 [2] 90 60 [2] be 60 [2] 81 7c }

  condition:
    any of them
}