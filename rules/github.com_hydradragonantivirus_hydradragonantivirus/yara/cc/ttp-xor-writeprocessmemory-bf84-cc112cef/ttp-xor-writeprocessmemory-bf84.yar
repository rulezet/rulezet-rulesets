rule TTP_XOR_WriteProcessMemory_bf84 {
  strings:
    $key_bf84 = { e8 f6 [2] da d4 [2] dc e1 [2] f2 e1 [2] cd fd }

  condition:
    any of them
}