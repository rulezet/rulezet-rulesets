rule TTP_XOR_WriteProcessMemory_bff0 {
  strings:
    $key_bff0 = { e8 82 [2] da a0 [2] dc 95 [2] f2 95 [2] cd 89 }

  condition:
    any of them
}