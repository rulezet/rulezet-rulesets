rule TTP_XOR_WriteProcessMemory_bfbb {
  strings:
    $key_bfbb = { e8 c9 [2] da eb [2] dc de [2] f2 de [2] cd c2 }

  condition:
    any of them
}