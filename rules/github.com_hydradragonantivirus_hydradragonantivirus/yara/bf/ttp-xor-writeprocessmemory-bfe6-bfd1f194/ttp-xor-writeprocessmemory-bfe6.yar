rule TTP_XOR_WriteProcessMemory_bfe6 {
  strings:
    $key_bfe6 = { e8 94 [2] da b6 [2] dc 83 [2] f2 83 [2] cd 9f }

  condition:
    any of them
}