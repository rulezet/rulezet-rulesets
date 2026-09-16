rule TTP_XOR_WriteProcessMemory_bfeb {
  strings:
    $key_bfeb = { e8 99 [2] da bb [2] dc 8e [2] f2 8e [2] cd 92 }

  condition:
    any of them
}