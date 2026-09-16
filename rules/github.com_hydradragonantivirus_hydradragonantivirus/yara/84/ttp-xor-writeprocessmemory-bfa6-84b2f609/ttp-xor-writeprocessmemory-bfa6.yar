rule TTP_XOR_WriteProcessMemory_bfa6 {
  strings:
    $key_bfa6 = { e8 d4 [2] da f6 [2] dc c3 [2] f2 c3 [2] cd df }

  condition:
    any of them
}