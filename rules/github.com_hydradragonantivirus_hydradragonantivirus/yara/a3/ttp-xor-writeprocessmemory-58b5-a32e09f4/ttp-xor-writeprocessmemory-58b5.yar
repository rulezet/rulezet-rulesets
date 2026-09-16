rule TTP_XOR_WriteProcessMemory_58b5 {
  strings:
    $key_58b5 = { 0f c7 [2] 3d e5 [2] 3b d0 [2] 15 d0 [2] 2a cc }

  condition:
    any of them
}