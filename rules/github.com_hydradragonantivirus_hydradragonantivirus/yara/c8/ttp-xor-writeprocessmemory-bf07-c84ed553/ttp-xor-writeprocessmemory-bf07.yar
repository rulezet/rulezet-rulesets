rule TTP_XOR_WriteProcessMemory_bf07 {
  strings:
    $key_bf07 = { e8 75 [2] da 57 [2] dc 62 [2] f2 62 [2] cd 7e }

  condition:
    any of them
}