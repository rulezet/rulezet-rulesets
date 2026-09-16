rule TTP_XOR_WriteProcessMemory_bf09 {
  strings:
    $key_bf09 = { e8 7b [2] da 59 [2] dc 6c [2] f2 6c [2] cd 70 }

  condition:
    any of them
}