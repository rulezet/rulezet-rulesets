rule TTP_XOR_WriteProcessMemory_07d4 {
  strings:
    $key_07d4 = { 50 a6 [2] 62 84 [2] 64 b1 [2] 4a b1 [2] 75 ad }

  condition:
    any of them
}