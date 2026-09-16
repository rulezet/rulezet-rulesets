rule TTP_XOR_WriteProcessMemory_bfe9 {
  strings:
    $key_bfe9 = { e8 9b [2] da b9 [2] dc 8c [2] f2 8c [2] cd 90 }

  condition:
    any of them
}