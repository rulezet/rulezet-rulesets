rule TTP_XOR_WriteProcessMemory_bf50 {
  strings:
    $key_bf50 = { e8 22 [2] da 00 [2] dc 35 [2] f2 35 [2] cd 29 }

  condition:
    any of them
}