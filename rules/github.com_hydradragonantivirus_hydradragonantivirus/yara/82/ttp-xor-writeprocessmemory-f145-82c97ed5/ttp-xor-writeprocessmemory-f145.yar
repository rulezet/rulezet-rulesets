rule TTP_XOR_WriteProcessMemory_f145 {
  strings:
    $key_f145 = { a6 37 [2] 94 15 [2] 92 20 [2] bc 20 [2] 83 3c }

  condition:
    any of them
}