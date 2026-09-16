rule TTP_XOR_WriteProcessMemory_bfb9 {
  strings:
    $key_bfb9 = { e8 cb [2] da e9 [2] dc dc [2] f2 dc [2] cd c0 }

  condition:
    any of them
}