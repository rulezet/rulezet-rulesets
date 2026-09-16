rule TTP_XOR_WriteProcessMemory_1576 {
  strings:
    $key_1576 = { 42 04 [2] 70 26 [2] 76 13 [2] 58 13 [2] 67 0f }

  condition:
    any of them
}