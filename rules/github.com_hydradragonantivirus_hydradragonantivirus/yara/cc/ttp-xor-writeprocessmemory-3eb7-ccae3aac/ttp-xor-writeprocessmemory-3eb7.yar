rule TTP_XOR_WriteProcessMemory_3eb7 {
  strings:
    $key_3eb7 = { 69 c5 [2] 5b e7 [2] 5d d2 [2] 73 d2 [2] 4c ce }

  condition:
    any of them
}