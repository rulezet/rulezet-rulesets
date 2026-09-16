rule TTP_XOR_WriteProcessMemory_70b0 {
  strings:
    $key_70b0 = { 27 c2 [2] 15 e0 [2] 13 d5 [2] 3d d5 [2] 02 c9 }

  condition:
    any of them
}