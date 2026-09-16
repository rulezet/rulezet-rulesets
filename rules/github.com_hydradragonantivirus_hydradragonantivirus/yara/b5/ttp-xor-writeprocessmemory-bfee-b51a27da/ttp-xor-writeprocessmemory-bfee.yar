rule TTP_XOR_WriteProcessMemory_bfee {
  strings:
    $key_bfee = { e8 9c [2] da be [2] dc 8b [2] f2 8b [2] cd 97 }

  condition:
    any of them
}