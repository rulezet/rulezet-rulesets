rule TTP_XOR_WriteProcessMemory_bf48 {
  strings:
    $key_bf48 = { e8 3a [2] da 18 [2] dc 2d [2] f2 2d [2] cd 31 }

  condition:
    any of them
}