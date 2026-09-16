rule TTP_XOR_WriteProcessMemory_bfa2 {
  strings:
    $key_bfa2 = { e8 d0 [2] da f2 [2] dc c7 [2] f2 c7 [2] cd db }

  condition:
    any of them
}