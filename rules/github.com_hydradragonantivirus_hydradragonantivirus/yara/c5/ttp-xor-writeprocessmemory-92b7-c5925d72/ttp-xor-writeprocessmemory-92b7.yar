rule TTP_XOR_WriteProcessMemory_92b7 {
  strings:
    $key_92b7 = { c5 c5 [2] f7 e7 [2] f1 d2 [2] df d2 [2] e0 ce }

  condition:
    any of them
}