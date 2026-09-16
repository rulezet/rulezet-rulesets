rule TTP_XOR_WriteProcessMemory_bff2 {
  strings:
    $key_bff2 = { e8 80 [2] da a2 [2] dc 97 [2] f2 97 [2] cd 8b }

  condition:
    any of them
}