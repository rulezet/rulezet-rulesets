rule TTP_XOR_WriteProcessMemory_bf32 {
  strings:
    $key_bf32 = { e8 40 [2] da 62 [2] dc 57 [2] f2 57 [2] cd 4b }

  condition:
    any of them
}