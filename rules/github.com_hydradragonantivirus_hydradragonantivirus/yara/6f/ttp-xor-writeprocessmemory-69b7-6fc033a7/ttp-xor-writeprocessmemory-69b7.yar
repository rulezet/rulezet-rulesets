rule TTP_XOR_WriteProcessMemory_69b7 {
  strings:
    $key_69b7 = { 3e c5 [2] 0c e7 [2] 0a d2 [2] 24 d2 [2] 1b ce }

  condition:
    any of them
}