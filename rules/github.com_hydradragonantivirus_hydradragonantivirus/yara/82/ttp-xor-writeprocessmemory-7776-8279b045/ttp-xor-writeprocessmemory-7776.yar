rule TTP_XOR_WriteProcessMemory_7776 {
  strings:
    $key_7776 = { 20 04 [2] 12 26 [2] 14 13 [2] 3a 13 [2] 05 0f }

  condition:
    any of them
}