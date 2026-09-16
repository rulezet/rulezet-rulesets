rule TTP_XOR_WriteProcessMemory_70a2 {
  strings:
    $key_70a2 = { 27 d0 [2] 15 f2 [2] 13 c7 [2] 3d c7 [2] 02 db }

  condition:
    any of them
}