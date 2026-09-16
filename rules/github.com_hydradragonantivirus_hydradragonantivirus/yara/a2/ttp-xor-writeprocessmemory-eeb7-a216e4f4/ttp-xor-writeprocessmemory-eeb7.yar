rule TTP_XOR_WriteProcessMemory_eeb7 {
  strings:
    $key_eeb7 = { b9 c5 [2] 8b e7 [2] 8d d2 [2] a3 d2 [2] 9c ce }

  condition:
    any of them
}