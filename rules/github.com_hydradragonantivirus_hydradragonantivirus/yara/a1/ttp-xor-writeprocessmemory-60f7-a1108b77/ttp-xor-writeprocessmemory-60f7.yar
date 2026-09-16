rule TTP_XOR_WriteProcessMemory_60f7 {
  strings:
    $key_60f7 = { 37 85 [2] 05 a7 [2] 03 92 [2] 2d 92 [2] 12 8e }

  condition:
    any of them
}