rule TTP_XOR_WriteProcessMemory_a8e7 {
  strings:
    $key_a8e7 = { ff 95 [2] cd b7 [2] cb 82 [2] e5 82 [2] da 9e }

  condition:
    any of them
}