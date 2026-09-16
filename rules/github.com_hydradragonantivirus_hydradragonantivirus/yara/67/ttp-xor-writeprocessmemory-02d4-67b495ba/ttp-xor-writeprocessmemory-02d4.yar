rule TTP_XOR_WriteProcessMemory_02d4 {
  strings:
    $key_02d4 = { 55 a6 [2] 67 84 [2] 61 b1 [2] 4f b1 [2] 70 ad }

  condition:
    any of them
}