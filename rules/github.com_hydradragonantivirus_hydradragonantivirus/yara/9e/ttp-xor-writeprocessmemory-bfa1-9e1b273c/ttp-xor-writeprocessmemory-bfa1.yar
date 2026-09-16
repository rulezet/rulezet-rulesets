rule TTP_XOR_WriteProcessMemory_bfa1 {
  strings:
    $key_bfa1 = { e8 d3 [2] da f1 [2] dc c4 [2] f2 c4 [2] cd d8 }

  condition:
    any of them
}