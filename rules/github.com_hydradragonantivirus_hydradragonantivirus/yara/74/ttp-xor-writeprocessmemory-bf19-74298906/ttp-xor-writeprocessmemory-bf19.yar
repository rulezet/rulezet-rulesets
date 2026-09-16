rule TTP_XOR_WriteProcessMemory_bf19 {
  strings:
    $key_bf19 = { e8 6b [2] da 49 [2] dc 7c [2] f2 7c [2] cd 60 }

  condition:
    any of them
}