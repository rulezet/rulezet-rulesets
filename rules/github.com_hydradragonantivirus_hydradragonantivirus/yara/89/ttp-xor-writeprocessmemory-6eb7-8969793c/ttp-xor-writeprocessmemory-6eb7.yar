rule TTP_XOR_WriteProcessMemory_6eb7 {
  strings:
    $key_6eb7 = { 39 c5 [2] 0b e7 [2] 0d d2 [2] 23 d2 [2] 1c ce }

  condition:
    any of them
}