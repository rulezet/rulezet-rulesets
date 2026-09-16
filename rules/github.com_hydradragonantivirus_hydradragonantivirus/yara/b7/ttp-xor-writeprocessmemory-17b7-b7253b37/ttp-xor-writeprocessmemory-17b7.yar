rule TTP_XOR_WriteProcessMemory_17b7 {
  strings:
    $key_17b7 = { 40 c5 [2] 72 e7 [2] 74 d2 [2] 5a d2 [2] 65 ce }

  condition:
    any of them
}