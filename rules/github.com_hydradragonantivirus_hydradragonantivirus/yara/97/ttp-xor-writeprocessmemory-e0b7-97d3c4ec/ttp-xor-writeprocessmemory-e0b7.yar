rule TTP_XOR_WriteProcessMemory_e0b7 {
  strings:
    $key_e0b7 = { b7 c5 [2] 85 e7 [2] 83 d2 [2] ad d2 [2] 92 ce }

  condition:
    any of them
}