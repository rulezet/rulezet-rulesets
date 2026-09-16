rule TTP_XOR_WriteProcessMemory_27b7 {
  strings:
    $key_27b7 = { 70 c5 [2] 42 e7 [2] 44 d2 [2] 6a d2 [2] 55 ce }

  condition:
    any of them
}