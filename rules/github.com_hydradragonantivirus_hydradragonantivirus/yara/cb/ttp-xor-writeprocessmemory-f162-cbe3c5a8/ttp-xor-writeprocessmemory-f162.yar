rule TTP_XOR_WriteProcessMemory_f162 {
  strings:
    $key_f162 = { a6 10 [2] 94 32 [2] 92 07 [2] bc 07 [2] 83 1b }

  condition:
    any of them
}