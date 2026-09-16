rule TTP_XOR_WriteProcessMemory_58a9 {
  strings:
    $key_58a9 = { 0f db [2] 3d f9 [2] 3b cc [2] 15 cc [2] 2a d0 }

  condition:
    any of them
}