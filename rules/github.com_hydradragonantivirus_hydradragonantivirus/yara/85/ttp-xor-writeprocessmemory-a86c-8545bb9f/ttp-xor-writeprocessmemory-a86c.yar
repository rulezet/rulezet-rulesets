rule TTP_XOR_WriteProcessMemory_a86c {
  strings:
    $key_a86c = { ff 1e [2] cd 3c [2] cb 09 [2] e5 09 [2] da 15 }

  condition:
    any of them
}