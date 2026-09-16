rule TTP_XOR_WriteProcessMemory_bf63 {
  strings:
    $key_bf63 = { e8 11 [2] da 33 [2] dc 06 [2] f2 06 [2] cd 1a }

  condition:
    any of them
}