rule TTP_XOR_WriteProcessMemory_bfbc {
  strings:
    $key_bfbc = { e8 ce [2] da ec [2] dc d9 [2] f2 d9 [2] cd c5 }

  condition:
    any of them
}