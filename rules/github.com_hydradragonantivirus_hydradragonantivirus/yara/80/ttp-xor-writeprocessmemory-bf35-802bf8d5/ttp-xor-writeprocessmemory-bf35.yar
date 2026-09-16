rule TTP_XOR_WriteProcessMemory_bf35 {
  strings:
    $key_bf35 = { e8 47 [2] da 65 [2] dc 50 [2] f2 50 [2] cd 4c }

  condition:
    any of them
}