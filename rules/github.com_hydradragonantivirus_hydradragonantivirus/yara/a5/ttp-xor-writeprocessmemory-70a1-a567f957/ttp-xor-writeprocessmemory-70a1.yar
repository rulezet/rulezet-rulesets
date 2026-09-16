rule TTP_XOR_WriteProcessMemory_70a1 {
  strings:
    $key_70a1 = { 27 d3 [2] 15 f1 [2] 13 c4 [2] 3d c4 [2] 02 d8 }

  condition:
    any of them
}