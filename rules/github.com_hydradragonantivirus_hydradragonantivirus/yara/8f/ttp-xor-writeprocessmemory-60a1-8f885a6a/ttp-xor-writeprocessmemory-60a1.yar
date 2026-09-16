rule TTP_XOR_WriteProcessMemory_60a1 {
  strings:
    $key_60a1 = { 37 d3 [2] 05 f1 [2] 03 c4 [2] 2d c4 [2] 12 d8 }

  condition:
    any of them
}