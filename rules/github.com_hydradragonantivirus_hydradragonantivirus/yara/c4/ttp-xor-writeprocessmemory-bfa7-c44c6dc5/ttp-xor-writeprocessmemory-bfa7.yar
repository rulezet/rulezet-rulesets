rule TTP_XOR_WriteProcessMemory_bfa7 {
  strings:
    $key_bfa7 = { e8 d5 [2] da f7 [2] dc c2 [2] f2 c2 [2] cd de }

  condition:
    any of them
}