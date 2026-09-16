rule TTP_XOR_WriteProcessMemory_bf92 {
  strings:
    $key_bf92 = { e8 e0 [2] da c2 [2] dc f7 [2] f2 f7 [2] cd eb }

  condition:
    any of them
}