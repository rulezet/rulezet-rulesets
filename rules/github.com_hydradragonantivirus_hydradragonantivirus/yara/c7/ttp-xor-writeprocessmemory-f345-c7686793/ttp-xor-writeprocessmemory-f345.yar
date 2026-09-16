rule TTP_XOR_WriteProcessMemory_f345 {
  strings:
    $key_f345 = { a4 37 [2] 96 15 [2] 90 20 [2] be 20 [2] 81 3c }

  condition:
    any of them
}