rule TTP_XOR_WriteProcessMemory_22d4 {
  strings:
    $key_22d4 = { 75 a6 [2] 47 84 [2] 41 b1 [2] 6f b1 [2] 50 ad }

  condition:
    any of them
}