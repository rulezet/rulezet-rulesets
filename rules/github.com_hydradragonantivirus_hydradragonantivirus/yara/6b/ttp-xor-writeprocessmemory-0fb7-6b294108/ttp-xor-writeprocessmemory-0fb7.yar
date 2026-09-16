rule TTP_XOR_WriteProcessMemory_0fb7 {
  strings:
    $key_0fb7 = { 58 c5 [2] 6a e7 [2] 6c d2 [2] 42 d2 [2] 7d ce }

  condition:
    any of them
}