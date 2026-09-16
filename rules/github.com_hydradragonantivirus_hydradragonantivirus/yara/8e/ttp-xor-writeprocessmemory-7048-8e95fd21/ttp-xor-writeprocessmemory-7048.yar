rule TTP_XOR_WriteProcessMemory_7048 {
  strings:
    $key_7048 = { 27 3a [2] 15 18 [2] 13 2d [2] 3d 2d [2] 02 31 }

  condition:
    any of them
}