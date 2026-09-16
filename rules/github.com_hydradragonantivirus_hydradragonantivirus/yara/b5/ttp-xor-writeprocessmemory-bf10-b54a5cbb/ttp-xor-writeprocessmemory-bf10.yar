rule TTP_XOR_WriteProcessMemory_bf10 {
  strings:
    $key_bf10 = { e8 62 [2] da 40 [2] dc 75 [2] f2 75 [2] cd 69 }

  condition:
    any of them
}