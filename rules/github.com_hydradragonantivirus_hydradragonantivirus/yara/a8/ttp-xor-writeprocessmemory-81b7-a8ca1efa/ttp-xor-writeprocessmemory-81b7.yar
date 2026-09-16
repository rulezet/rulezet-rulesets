rule TTP_XOR_WriteProcessMemory_81b7 {
  strings:
    $key_81b7 = { d6 c5 [2] e4 e7 [2] e2 d2 [2] cc d2 [2] f3 ce }

  condition:
    any of them
}