rule TTP_XOR_WriteProcessMemory_60b7 {
  strings:
    $key_60b7 = { 37 c5 [2] 05 e7 [2] 03 d2 [2] 2d d2 [2] 12 ce }

  condition:
    any of them
}