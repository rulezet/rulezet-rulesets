rule TTP_XOR_WriteProcessMemory_60f6 {
  strings:
    $key_60f6 = { 37 84 [2] 05 a6 [2] 03 93 [2] 2d 93 [2] 12 8f }

  condition:
    any of them
}