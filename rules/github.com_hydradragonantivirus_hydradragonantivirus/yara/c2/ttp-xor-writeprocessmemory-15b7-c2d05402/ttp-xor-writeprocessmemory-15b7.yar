rule TTP_XOR_WriteProcessMemory_15b7 {
  strings:
    $key_15b7 = { 42 c5 [2] 70 e7 [2] 76 d2 [2] 58 d2 [2] 67 ce }

  condition:
    any of them
}