rule TTP_XOR_WriteProcessMemory_bfea {
  strings:
    $key_bfea = { e8 98 [2] da ba [2] dc 8f [2] f2 8f [2] cd 93 }

  condition:
    any of them
}