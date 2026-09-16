rule TTP_XOR_WriteProcessMemory_bfb7 {
  strings:
    $key_bfb7 = { e8 c5 [2] da e7 [2] dc d2 [2] f2 d2 [2] cd ce }

  condition:
    any of them
}