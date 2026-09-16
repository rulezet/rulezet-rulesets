rule TTP_XOR_WriteProcessMemory_a884 {
  strings:
    $key_a884 = { ff f6 [2] cd d4 [2] cb e1 [2] e5 e1 [2] da fd }

  condition:
    any of them
}