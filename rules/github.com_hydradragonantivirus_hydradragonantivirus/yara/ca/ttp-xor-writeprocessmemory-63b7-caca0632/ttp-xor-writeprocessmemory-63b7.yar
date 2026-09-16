rule TTP_XOR_WriteProcessMemory_63b7 {
  strings:
    $key_63b7 = { 34 c5 [2] 06 e7 [2] 00 d2 [2] 2e d2 [2] 11 ce }

  condition:
    any of them
}