rule TTP_XOR_WriteProcessMemory_46b7 {
  strings:
    $key_46b7 = { 11 c5 [2] 23 e7 [2] 25 d2 [2] 0b d2 [2] 34 ce }

  condition:
    any of them
}