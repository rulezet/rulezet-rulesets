rule TTP_XOR_WriteProcessMemory_bfe7 {
  strings:
    $key_bfe7 = { e8 95 [2] da b7 [2] dc 82 [2] f2 82 [2] cd 9e }

  condition:
    any of them
}