rule TTP_XOR_WriteProcessMemory_60a5 {
  strings:
    $key_60a5 = { 37 d7 [2] 05 f5 [2] 03 c0 [2] 2d c0 [2] 12 dc }

  condition:
    any of them
}