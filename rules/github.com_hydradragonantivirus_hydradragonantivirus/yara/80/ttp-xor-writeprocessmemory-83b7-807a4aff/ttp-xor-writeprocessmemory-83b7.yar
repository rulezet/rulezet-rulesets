rule TTP_XOR_WriteProcessMemory_83b7 {
  strings:
    $key_83b7 = { d4 c5 [2] e6 e7 [2] e0 d2 [2] ce d2 [2] f1 ce }

  condition:
    any of them
}