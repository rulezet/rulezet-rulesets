rule TTP_XOR_WriteProcessMemory_70a7 {
  strings:
    $key_70a7 = { 27 d5 [2] 15 f7 [2] 13 c2 [2] 3d c2 [2] 02 de }

  condition:
    any of them
}