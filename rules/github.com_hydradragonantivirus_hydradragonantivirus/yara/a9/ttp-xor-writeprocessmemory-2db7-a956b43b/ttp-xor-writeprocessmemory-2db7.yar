rule TTP_XOR_WriteProcessMemory_2db7 {
  strings:
    $key_2db7 = { 7a c5 [2] 48 e7 [2] 4e d2 [2] 60 d2 [2] 5f ce }

  condition:
    any of them
}