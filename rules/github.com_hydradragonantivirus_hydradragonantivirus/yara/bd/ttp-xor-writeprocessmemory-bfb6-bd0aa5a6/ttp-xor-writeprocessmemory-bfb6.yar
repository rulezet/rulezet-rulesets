rule TTP_XOR_WriteProcessMemory_bfb6 {
  strings:
    $key_bfb6 = { e8 c4 [2] da e6 [2] dc d3 [2] f2 d3 [2] cd cf }

  condition:
    any of them
}