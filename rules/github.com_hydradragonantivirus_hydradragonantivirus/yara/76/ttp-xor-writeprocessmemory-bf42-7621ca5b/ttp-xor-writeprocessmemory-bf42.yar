rule TTP_XOR_WriteProcessMemory_bf42 {
  strings:
    $key_bf42 = { e8 30 [2] da 12 [2] dc 27 [2] f2 27 [2] cd 3b }

  condition:
    any of them
}