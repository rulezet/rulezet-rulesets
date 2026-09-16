rule TTP_XOR_WriteProcessMemory_0db7 {
  strings:
    $key_0db7 = { 5a c5 [2] 68 e7 [2] 6e d2 [2] 40 d2 [2] 7f ce }

  condition:
    any of them
}