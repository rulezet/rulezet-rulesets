rule TTP_XOR_WriteProcessMemory_bfad {
  strings:
    $key_bfad = { e8 df [2] da fd [2] dc c8 [2] f2 c8 [2] cd d4 }

  condition:
    any of them
}