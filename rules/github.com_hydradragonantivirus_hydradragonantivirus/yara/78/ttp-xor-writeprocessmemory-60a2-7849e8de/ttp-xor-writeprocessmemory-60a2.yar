rule TTP_XOR_WriteProcessMemory_60a2 {
  strings:
    $key_60a2 = { 37 d0 [2] 05 f2 [2] 03 c7 [2] 2d c7 [2] 12 db }

  condition:
    any of them
}