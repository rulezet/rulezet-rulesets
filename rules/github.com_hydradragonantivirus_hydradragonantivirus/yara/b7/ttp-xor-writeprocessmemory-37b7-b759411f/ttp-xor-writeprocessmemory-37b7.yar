rule TTP_XOR_WriteProcessMemory_37b7 {
  strings:
    $key_37b7 = { 60 c5 [2] 52 e7 [2] 54 d2 [2] 7a d2 [2] 45 ce }

  condition:
    any of them
}