rule TTP_XOR_WriteProcessMemory_70a5 {
  strings:
    $key_70a5 = { 27 d7 [2] 15 f5 [2] 13 c0 [2] 3d c0 [2] 02 dc }

  condition:
    any of them
}