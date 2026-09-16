rule TTP_XOR_WriteProcessMemory_bf98 {
  strings:
    $key_bf98 = { e8 ea [2] da c8 [2] dc fd [2] f2 fd [2] cd e1 }

  condition:
    any of them
}