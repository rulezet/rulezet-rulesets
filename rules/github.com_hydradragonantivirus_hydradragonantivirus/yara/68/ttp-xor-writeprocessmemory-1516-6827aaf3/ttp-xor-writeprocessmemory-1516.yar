rule TTP_XOR_WriteProcessMemory_1516 {
  strings:
    $key_1516 = { 42 64 [2] 70 46 [2] 76 73 [2] 58 73 [2] 67 6f }

  condition:
    any of them
}