rule TTP_XOR_WriteProcessMemory_4dd4 {
  strings:
    $key_4dd4 = { 1a a6 [2] 28 84 [2] 2e b1 [2] 00 b1 [2] 3f ad }

  condition:
    any of them
}