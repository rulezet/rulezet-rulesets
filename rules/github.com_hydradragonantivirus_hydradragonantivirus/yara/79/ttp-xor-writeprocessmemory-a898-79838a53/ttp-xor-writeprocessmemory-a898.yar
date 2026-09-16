rule TTP_XOR_WriteProcessMemory_a898 {
  strings:
    $key_a898 = { ff ea [2] cd c8 [2] cb fd [2] e5 fd [2] da e1 }

  condition:
    any of them
}