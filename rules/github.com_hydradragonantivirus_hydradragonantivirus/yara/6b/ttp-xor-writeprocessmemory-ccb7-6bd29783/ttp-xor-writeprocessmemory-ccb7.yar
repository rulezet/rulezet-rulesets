rule TTP_XOR_WriteProcessMemory_ccb7 {
  strings:
    $key_ccb7 = { 9b c5 [2] a9 e7 [2] af d2 [2] 81 d2 [2] be ce }

  condition:
    any of them
}