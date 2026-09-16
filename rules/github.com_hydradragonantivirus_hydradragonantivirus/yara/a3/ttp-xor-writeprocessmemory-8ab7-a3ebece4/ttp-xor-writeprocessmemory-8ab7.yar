rule TTP_XOR_WriteProcessMemory_8ab7 {
  strings:
    $key_8ab7 = { dd c5 [2] ef e7 [2] e9 d2 [2] c7 d2 [2] f8 ce }

  condition:
    any of them
}