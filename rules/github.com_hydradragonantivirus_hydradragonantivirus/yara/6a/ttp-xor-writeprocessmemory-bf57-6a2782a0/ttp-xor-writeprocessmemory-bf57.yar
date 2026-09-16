rule TTP_XOR_WriteProcessMemory_bf57 {
  strings:
    $key_bf57 = { e8 25 [2] da 07 [2] dc 32 [2] f2 32 [2] cd 2e }

  condition:
    any of them
}