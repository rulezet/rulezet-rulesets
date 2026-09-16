rule TTP_XOR_WriteProcessMemory_a8a7 {
  strings:
    $key_a8a7 = { ff d5 [2] cd f7 [2] cb c2 [2] e5 c2 [2] da de }

  condition:
    any of them
}