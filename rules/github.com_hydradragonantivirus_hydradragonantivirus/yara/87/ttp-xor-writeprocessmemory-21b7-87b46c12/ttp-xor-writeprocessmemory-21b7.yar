rule TTP_XOR_WriteProcessMemory_21b7 {
  strings:
    $key_21b7 = { 76 c5 [2] 44 e7 [2] 42 d2 [2] 6c d2 [2] 53 ce }

  condition:
    any of them
}