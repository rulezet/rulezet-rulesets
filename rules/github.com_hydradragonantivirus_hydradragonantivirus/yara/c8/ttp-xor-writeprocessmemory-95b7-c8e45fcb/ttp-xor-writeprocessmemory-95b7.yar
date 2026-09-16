rule TTP_XOR_WriteProcessMemory_95b7 {
  strings:
    $key_95b7 = { c2 c5 [2] f0 e7 [2] f6 d2 [2] d8 d2 [2] e7 ce }

  condition:
    any of them
}