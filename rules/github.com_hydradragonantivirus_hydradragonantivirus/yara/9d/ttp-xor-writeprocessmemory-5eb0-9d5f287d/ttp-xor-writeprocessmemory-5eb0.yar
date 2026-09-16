rule TTP_XOR_WriteProcessMemory_5eb0 {
  strings:
    $key_5eb0 = { 09 c2 [2] 3b e0 [2] 3d d5 [2] 13 d5 [2] 2c c9 }

  condition:
    any of them
}