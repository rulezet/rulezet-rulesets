rule TTP_XOR_WriteProcessMemory_85b7 {
  strings:
    $key_85b7 = { d2 c5 [2] e0 e7 [2] e6 d2 [2] c8 d2 [2] f7 ce }

  condition:
    any of them
}