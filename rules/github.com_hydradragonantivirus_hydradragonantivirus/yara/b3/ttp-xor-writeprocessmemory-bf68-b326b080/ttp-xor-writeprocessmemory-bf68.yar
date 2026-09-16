rule TTP_XOR_WriteProcessMemory_bf68 {
  strings:
    $key_bf68 = { e8 1a [2] da 38 [2] dc 0d [2] f2 0d [2] cd 11 }

  condition:
    any of them
}