rule TTP_XOR_WriteProcessMemory_bf02 {
  strings:
    $key_bf02 = { e8 70 [2] da 52 [2] dc 67 [2] f2 67 [2] cd 7b }

  condition:
    any of them
}