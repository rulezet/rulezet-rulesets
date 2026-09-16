rule TTP_XOR_WriteProcessMemory_bfb3 {
  strings:
    $key_bfb3 = { e8 c1 [2] da e3 [2] dc d6 [2] f2 d6 [2] cd ca }

  condition:
    any of them
}