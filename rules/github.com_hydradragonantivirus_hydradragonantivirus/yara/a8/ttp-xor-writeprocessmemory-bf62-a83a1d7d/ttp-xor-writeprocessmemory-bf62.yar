rule TTP_XOR_WriteProcessMemory_bf62 {
  strings:
    $key_bf62 = { e8 10 [2] da 32 [2] dc 07 [2] f2 07 [2] cd 1b }

  condition:
    any of them
}