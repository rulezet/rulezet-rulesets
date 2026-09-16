rule TTP_XOR_WriteProcessMemory_f105 {
  strings:
    $key_f105 = { a6 77 [2] 94 55 [2] 92 60 [2] bc 60 [2] 83 7c }

  condition:
    any of them
}