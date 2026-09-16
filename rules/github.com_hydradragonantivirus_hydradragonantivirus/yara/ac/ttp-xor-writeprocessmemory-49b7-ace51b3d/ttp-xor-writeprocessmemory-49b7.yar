rule TTP_XOR_WriteProcessMemory_49b7 {
  strings:
    $key_49b7 = { 1e c5 [2] 2c e7 [2] 2a d2 [2] 04 d2 [2] 3b ce }

  condition:
    any of them
}