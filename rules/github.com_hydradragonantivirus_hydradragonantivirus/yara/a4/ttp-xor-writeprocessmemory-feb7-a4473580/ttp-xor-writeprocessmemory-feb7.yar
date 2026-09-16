rule TTP_XOR_WriteProcessMemory_feb7 {
  strings:
    $key_feb7 = { a9 c5 [2] 9b e7 [2] 9d d2 [2] b3 d2 [2] 8c ce }

  condition:
    any of them
}