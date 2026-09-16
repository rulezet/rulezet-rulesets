rule TTP_XOR_WriteProcessMemory_4db7 {
  strings:
    $key_4db7 = { 1a c5 [2] 28 e7 [2] 2e d2 [2] 00 d2 [2] 3f ce }

  condition:
    any of them
}