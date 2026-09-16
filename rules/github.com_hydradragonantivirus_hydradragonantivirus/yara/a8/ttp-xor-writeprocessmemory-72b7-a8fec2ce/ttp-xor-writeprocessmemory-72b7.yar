rule TTP_XOR_WriteProcessMemory_72b7 {
  strings:
    $key_72b7 = { 25 c5 [2] 17 e7 [2] 11 d2 [2] 3f d2 [2] 00 ce }

  condition:
    any of them
}