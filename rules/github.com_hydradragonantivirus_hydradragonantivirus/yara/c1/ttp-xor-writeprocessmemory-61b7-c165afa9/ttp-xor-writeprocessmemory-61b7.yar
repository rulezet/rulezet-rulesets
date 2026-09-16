rule TTP_XOR_WriteProcessMemory_61b7 {
  strings:
    $key_61b7 = { 36 c5 [2] 04 e7 [2] 02 d2 [2] 2c d2 [2] 13 ce }

  condition:
    any of them
}