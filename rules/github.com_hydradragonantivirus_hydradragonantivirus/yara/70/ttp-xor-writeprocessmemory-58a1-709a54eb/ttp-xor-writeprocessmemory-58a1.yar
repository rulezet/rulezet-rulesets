rule TTP_XOR_WriteProcessMemory_58a1 {
  strings:
    $key_58a1 = { 0f d3 [2] 3d f1 [2] 3b c4 [2] 15 c4 [2] 2a d8 }

  condition:
    any of them
}