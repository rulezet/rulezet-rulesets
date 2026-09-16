rule TTP_XOR_WriteProcessMemory_65b7 {
  strings:
    $key_65b7 = { 32 c5 [2] 00 e7 [2] 06 d2 [2] 28 d2 [2] 17 ce }

  condition:
    any of them
}