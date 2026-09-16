rule TTP_XOR_WriteProcessMemory_bfca {
  strings:
    $key_bfca = { e8 b8 [2] da 9a [2] dc af [2] f2 af [2] cd b3 }

  condition:
    any of them
}