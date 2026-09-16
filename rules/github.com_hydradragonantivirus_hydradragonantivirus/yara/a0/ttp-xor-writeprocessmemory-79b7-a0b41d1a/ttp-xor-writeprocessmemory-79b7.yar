rule TTP_XOR_WriteProcessMemory_79b7 {
  strings:
    $key_79b7 = { 2e c5 [2] 1c e7 [2] 1a d2 [2] 34 d2 [2] 0b ce }

  condition:
    any of them
}