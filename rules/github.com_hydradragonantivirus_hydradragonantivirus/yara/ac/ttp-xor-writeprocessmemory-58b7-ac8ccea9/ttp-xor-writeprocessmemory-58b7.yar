rule TTP_XOR_WriteProcessMemory_58b7 {
  strings:
    $key_58b7 = { 0f c5 [2] 3d e7 [2] 3b d2 [2] 15 d2 [2] 2a ce }

  condition:
    any of them
}