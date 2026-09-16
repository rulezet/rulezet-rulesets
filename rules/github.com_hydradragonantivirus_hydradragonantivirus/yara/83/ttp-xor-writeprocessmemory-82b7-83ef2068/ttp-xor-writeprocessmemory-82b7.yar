rule TTP_XOR_WriteProcessMemory_82b7 {
  strings:
    $key_82b7 = { d5 c5 [2] e7 e7 [2] e1 d2 [2] cf d2 [2] f0 ce }

  condition:
    any of them
}