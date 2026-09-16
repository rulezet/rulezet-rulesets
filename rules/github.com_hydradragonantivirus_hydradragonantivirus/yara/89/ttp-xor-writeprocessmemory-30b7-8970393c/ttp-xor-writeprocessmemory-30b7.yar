rule TTP_XOR_WriteProcessMemory_30b7 {
  strings:
    $key_30b7 = { 67 c5 [2] 55 e7 [2] 53 d2 [2] 7d d2 [2] 42 ce }

  condition:
    any of them
}