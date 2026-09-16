rule TTP_XOR_WriteProcessMemory_a843 {
  strings:
    $key_a843 = { ff 31 [2] cd 13 [2] cb 26 [2] e5 26 [2] da 3a }

  condition:
    any of them
}