rule TTP_XOR_WriteProcessMemory_11b7 {
  strings:
    $key_11b7 = { 46 c5 [2] 74 e7 [2] 72 d2 [2] 5c d2 [2] 63 ce }

  condition:
    any of them
}