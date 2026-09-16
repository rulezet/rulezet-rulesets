rule TTP_XOR_WriteProcessMemory_07b7 {
  strings:
    $key_07b7 = { 50 c5 [2] 62 e7 [2] 64 d2 [2] 4a d2 [2] 75 ce }

  condition:
    any of them
}