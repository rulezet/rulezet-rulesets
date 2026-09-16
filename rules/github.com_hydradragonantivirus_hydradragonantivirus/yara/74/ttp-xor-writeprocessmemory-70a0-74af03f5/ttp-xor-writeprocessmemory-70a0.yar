rule TTP_XOR_WriteProcessMemory_70a0 {
  strings:
    $key_70a0 = { 27 d2 [2] 15 f0 [2] 13 c5 [2] 3d c5 [2] 02 d9 }

  condition:
    any of them
}