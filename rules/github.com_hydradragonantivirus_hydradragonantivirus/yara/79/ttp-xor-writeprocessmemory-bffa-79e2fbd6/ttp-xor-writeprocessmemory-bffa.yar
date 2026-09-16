rule TTP_XOR_WriteProcessMemory_bffa {
  strings:
    $key_bffa = { e8 88 [2] da aa [2] dc 9f [2] f2 9f [2] cd 83 }

  condition:
    any of them
}