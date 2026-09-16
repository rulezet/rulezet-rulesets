rule TTP_XOR_WriteProcessMemory_a8a1 {
  strings:
    $key_a8a1 = { ff d3 [2] cd f1 [2] cb c4 [2] e5 c4 [2] da d8 }

  condition:
    any of them
}