rule TTP_XOR_WriteProcessMemory_7fb7 {
  strings:
    $key_7fb7 = { 28 c5 [2] 1a e7 [2] 1c d2 [2] 32 d2 [2] 0d ce }

  condition:
    any of them
}