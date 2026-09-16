rule TTP_XOR_WriteProcessMemory_22b7 {
  strings:
    $key_22b7 = { 75 c5 [2] 47 e7 [2] 41 d2 [2] 6f d2 [2] 50 ce }

  condition:
    any of them
}