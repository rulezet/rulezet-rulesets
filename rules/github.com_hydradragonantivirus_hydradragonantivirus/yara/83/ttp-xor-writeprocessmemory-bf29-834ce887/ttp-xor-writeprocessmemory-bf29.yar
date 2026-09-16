rule TTP_XOR_WriteProcessMemory_bf29 {
  strings:
    $key_bf29 = { e8 5b [2] da 79 [2] dc 4c [2] f2 4c [2] cd 50 }

  condition:
    any of them
}