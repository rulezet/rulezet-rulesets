rule TTP_XOR_WriteProcessMemory_40b7 {
  strings:
    $key_40b7 = { 17 c5 [2] 25 e7 [2] 23 d2 [2] 0d d2 [2] 32 ce }

  condition:
    any of them
}