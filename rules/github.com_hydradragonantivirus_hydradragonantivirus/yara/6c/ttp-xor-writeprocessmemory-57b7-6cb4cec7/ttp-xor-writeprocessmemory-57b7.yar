rule TTP_XOR_WriteProcessMemory_57b7 {
  strings:
    $key_57b7 = { 00 c5 [2] 32 e7 [2] 34 d2 [2] 1a d2 [2] 25 ce }

  condition:
    any of them
}