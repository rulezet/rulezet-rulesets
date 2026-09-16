rule TTP_XOR_WriteProcessMemory_808b {
  strings:
    $key_808b = { d7 f9 [2] e5 db [2] e3 ee [2] cd ee [2] f2 f2 }

  condition:
    any of them
}