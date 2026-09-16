rule TTP_XOR_WriteProcessMemory_70a4 {
  strings:
    $key_70a4 = { 27 d6 [2] 15 f4 [2] 13 c1 [2] 3d c1 [2] 02 dd }

  condition:
    any of them
}