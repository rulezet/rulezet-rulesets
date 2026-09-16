rule TTP_XOR_WriteProcessMemory_f176 {
  strings:
    $key_f176 = { a6 04 [2] 94 26 [2] 92 13 [2] bc 13 [2] 83 0f }

  condition:
    any of them
}