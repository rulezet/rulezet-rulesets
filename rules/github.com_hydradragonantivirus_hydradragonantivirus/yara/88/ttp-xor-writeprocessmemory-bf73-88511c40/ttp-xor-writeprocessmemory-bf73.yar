rule TTP_XOR_WriteProcessMemory_bf73 {
  strings:
    $key_bf73 = { e8 01 [2] da 23 [2] dc 16 [2] f2 16 [2] cd 0a }

  condition:
    any of them
}