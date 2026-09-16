rule TTP_XOR_WriteProcessMemory_f166 {
  strings:
    $key_f166 = { a6 14 [2] 94 36 [2] 92 03 [2] bc 03 [2] 83 1f }

  condition:
    any of them
}