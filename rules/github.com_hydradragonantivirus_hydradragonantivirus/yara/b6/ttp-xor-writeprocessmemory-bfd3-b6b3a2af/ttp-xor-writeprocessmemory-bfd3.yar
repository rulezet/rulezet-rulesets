rule TTP_XOR_WriteProcessMemory_bfd3 {
  strings:
    $key_bfd3 = { e8 a1 [2] da 83 [2] dc b6 [2] f2 b6 [2] cd aa }

  condition:
    any of them
}