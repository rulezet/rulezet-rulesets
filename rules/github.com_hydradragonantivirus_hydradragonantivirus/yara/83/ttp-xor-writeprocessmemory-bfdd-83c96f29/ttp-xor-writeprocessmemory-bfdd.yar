rule TTP_XOR_WriteProcessMemory_bfdd {
  strings:
    $key_bfdd = { e8 af [2] da 8d [2] dc b8 [2] f2 b8 [2] cd a4 }

  condition:
    any of them
}