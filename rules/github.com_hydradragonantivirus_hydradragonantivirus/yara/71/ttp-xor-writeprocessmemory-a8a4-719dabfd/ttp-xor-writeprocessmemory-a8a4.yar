rule TTP_XOR_WriteProcessMemory_a8a4 {
  strings:
    $key_a8a4 = { ff d6 [2] cd f4 [2] cb c1 [2] e5 c1 [2] da dd }

  condition:
    any of them
}