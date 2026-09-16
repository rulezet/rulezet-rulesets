rule TTP_XOR_WriteProcessMemory_25b7 {
  strings:
    $key_25b7 = { 72 c5 [2] 40 e7 [2] 46 d2 [2] 68 d2 [2] 57 ce }

  condition:
    any of them
}