rule TTP_XOR_WriteProcessMemory_4eb7 {
  strings:
    $key_4eb7 = { 19 c5 [2] 2b e7 [2] 2d d2 [2] 03 d2 [2] 3c ce }

  condition:
    any of them
}