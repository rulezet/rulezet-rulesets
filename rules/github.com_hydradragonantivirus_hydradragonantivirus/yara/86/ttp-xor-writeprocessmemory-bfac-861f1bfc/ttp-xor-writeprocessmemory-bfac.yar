rule TTP_XOR_WriteProcessMemory_bfac {
  strings:
    $key_bfac = { e8 de [2] da fc [2] dc c9 [2] f2 c9 [2] cd d5 }

  condition:
    any of them
}