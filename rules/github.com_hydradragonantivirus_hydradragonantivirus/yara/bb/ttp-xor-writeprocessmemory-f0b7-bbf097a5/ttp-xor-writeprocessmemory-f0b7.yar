rule TTP_XOR_WriteProcessMemory_f0b7 {
  strings:
    $key_f0b7 = { a7 c5 [2] 95 e7 [2] 93 d2 [2] bd d2 [2] 82 ce }

  condition:
    any of them
}