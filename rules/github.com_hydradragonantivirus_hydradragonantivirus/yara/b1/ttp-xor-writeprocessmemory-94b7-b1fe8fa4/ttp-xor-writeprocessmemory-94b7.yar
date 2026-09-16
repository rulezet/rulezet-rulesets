rule TTP_XOR_WriteProcessMemory_94b7 {
  strings:
    $key_94b7 = { c3 c5 [2] f1 e7 [2] f7 d2 [2] d9 d2 [2] e6 ce }

  condition:
    any of them
}