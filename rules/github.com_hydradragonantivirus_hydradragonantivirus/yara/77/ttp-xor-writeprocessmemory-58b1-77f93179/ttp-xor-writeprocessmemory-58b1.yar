rule TTP_XOR_WriteProcessMemory_58b1 {
  strings:
    $key_58b1 = { 0f c3 [2] 3d e1 [2] 3b d4 [2] 15 d4 [2] 2a c8 }

  condition:
    any of them
}