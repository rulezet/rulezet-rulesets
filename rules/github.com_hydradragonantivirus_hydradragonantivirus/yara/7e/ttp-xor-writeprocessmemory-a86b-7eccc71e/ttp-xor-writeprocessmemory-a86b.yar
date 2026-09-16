rule TTP_XOR_WriteProcessMemory_a86b {
  strings:
    $key_a86b = { ff 19 [2] cd 3b [2] cb 0e [2] e5 0e [2] da 12 }

  condition:
    any of them
}