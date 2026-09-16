rule TTP_XOR_WriteProcessMemory_a8e2 {
  strings:
    $key_a8e2 = { ff 90 [2] cd b2 [2] cb 87 [2] e5 87 [2] da 9b }

  condition:
    any of them
}