rule TTP_XOR_WriteProcessMemory_60d4 {
  strings:
    $key_60d4 = { 37 a6 [2] 05 84 [2] 03 b1 [2] 2d b1 [2] 12 ad }

  condition:
    any of them
}