rule TTP_XOR_WriteProcessMemory_e9b7 {
  strings:
    $key_e9b7 = { be c5 [2] 8c e7 [2] 8a d2 [2] a4 d2 [2] 9b ce }

  condition:
    any of them
}