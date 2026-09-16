rule TTP_XOR_WriteProcessMemory_48b1 {
  strings:
    $key_48b1 = { 1f c3 [2] 2d e1 [2] 2b d4 [2] 05 d4 [2] 3a c8 }

  condition:
    any of them
}