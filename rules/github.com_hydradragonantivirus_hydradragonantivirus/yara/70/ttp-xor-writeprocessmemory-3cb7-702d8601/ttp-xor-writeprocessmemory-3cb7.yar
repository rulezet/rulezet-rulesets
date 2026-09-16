rule TTP_XOR_WriteProcessMemory_3cb7 {
  strings:
    $key_3cb7 = { 6b c5 [2] 59 e7 [2] 5f d2 [2] 71 d2 [2] 4e ce }

  condition:
    any of them
}