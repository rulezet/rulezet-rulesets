rule TTP_XOR_WriteProcessMemory_f172 {
  strings:
    $key_f172 = { a6 00 [2] 94 22 [2] 92 17 [2] bc 17 [2] 83 0b }

  condition:
    any of them
}