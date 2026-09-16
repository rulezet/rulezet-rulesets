rule TTP_XOR_WriteProcessMemory_60a3 {
  strings:
    $key_60a3 = { 37 d1 [2] 05 f3 [2] 03 c6 [2] 2d c6 [2] 12 da }

  condition:
    any of them
}