rule TTP_XOR_WriteProcessMemory_3fb7 {
  strings:
    $key_3fb7 = { 68 c5 [2] 5a e7 [2] 5c d2 [2] 72 d2 [2] 4d ce }

  condition:
    any of them
}