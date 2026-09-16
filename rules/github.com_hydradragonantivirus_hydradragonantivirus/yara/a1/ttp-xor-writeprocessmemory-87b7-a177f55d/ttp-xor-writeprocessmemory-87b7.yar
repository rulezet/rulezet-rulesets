rule TTP_XOR_WriteProcessMemory_87b7 {
  strings:
    $key_87b7 = { d0 c5 [2] e2 e7 [2] e4 d2 [2] ca d2 [2] f5 ce }

  condition:
    any of them
}