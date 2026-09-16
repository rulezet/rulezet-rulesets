rule TTP_XOR_WriteProcessMemory_bf45 {
  strings:
    $key_bf45 = { e8 37 [2] da 15 [2] dc 20 [2] f2 20 [2] cd 3c }

  condition:
    any of them
}