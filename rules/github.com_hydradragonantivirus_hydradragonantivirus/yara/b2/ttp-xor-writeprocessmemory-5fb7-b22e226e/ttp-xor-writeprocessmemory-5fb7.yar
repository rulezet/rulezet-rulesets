rule TTP_XOR_WriteProcessMemory_5fb7 {
  strings:
    $key_5fb7 = { 08 c5 [2] 3a e7 [2] 3c d2 [2] 12 d2 [2] 2d ce }

  condition:
    any of them
}