rule TTP_XOR_WriteProcessMemory_74b7 {
  strings:
    $key_74b7 = { 23 c5 [2] 11 e7 [2] 17 d2 [2] 39 d2 [2] 06 ce }

  condition:
    any of them
}