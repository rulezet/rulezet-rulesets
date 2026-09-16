rule TTP_XOR_WriteProcessMemory_68b7 {
  strings:
    $key_68b7 = { 3f c5 [2] 0d e7 [2] 0b d2 [2] 25 d2 [2] 1a ce }

  condition:
    any of them
}