rule TTP_XOR_WriteProcessMemory_3db7 {
  strings:
    $key_3db7 = { 6a c5 [2] 58 e7 [2] 5e d2 [2] 70 d2 [2] 4f ce }

  condition:
    any of them
}