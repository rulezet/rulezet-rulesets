rule TTP_XOR_WriteProcessMemory_f125 {
  strings:
    $key_f125 = { a6 57 [2] 94 75 [2] 92 40 [2] bc 40 [2] 83 5c }

  condition:
    any of them
}