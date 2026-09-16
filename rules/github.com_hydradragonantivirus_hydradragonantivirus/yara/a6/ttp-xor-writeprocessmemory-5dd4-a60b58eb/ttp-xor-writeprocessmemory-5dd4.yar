rule TTP_XOR_WriteProcessMemory_5dd4 {
  strings:
    $key_5dd4 = { 0a a6 [2] 38 84 [2] 3e b1 [2] 10 b1 [2] 2f ad }

  condition:
    any of them
}