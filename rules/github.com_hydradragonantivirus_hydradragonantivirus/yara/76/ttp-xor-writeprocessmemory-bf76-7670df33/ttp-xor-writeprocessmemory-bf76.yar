rule TTP_XOR_WriteProcessMemory_bf76 {
  strings:
    $key_bf76 = { e8 04 [2] da 26 [2] dc 13 [2] f2 13 [2] cd 0f }

  condition:
    any of them
}