rule TTP_XOR_WriteProcessMemory_bf13 {
  strings:
    $key_bf13 = { e8 61 [2] da 43 [2] dc 76 [2] f2 76 [2] cd 6a }

  condition:
    any of them
}