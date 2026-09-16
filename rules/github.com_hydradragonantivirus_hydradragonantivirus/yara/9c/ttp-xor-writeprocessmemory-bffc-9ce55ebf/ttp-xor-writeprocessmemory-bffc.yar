rule TTP_XOR_WriteProcessMemory_bffc {
  strings:
    $key_bffc = { e8 8e [2] da ac [2] dc 99 [2] f2 99 [2] cd 85 }

  condition:
    any of them
}