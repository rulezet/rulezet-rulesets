rule TTP_XOR_WriteProcessMemory_78b7 {
  strings:
    $key_78b7 = { 2f c5 [2] 1d e7 [2] 1b d2 [2] 35 d2 [2] 0a ce }

  condition:
    any of them
}