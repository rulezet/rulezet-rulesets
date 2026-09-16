rule TTP_XOR_WriteProcessMemory_44b7 {
  strings:
    $key_44b7 = { 13 c5 [2] 21 e7 [2] 27 d2 [2] 09 d2 [2] 36 ce }

  condition:
    any of them
}