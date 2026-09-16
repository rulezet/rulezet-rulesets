rule TTP_XOR_WriteProcessMemory_bff5 {
  strings:
    $key_bff5 = { e8 87 [2] da a5 [2] dc 90 [2] f2 90 [2] cd 8c }

  condition:
    any of them
}