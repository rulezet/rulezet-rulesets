rule TTP_XOR_WriteProcessMemory_0776 {
  strings:
    $key_0776 = { 50 04 [2] 62 26 [2] 64 13 [2] 4a 13 [2] 75 0f }

  condition:
    any of them
}