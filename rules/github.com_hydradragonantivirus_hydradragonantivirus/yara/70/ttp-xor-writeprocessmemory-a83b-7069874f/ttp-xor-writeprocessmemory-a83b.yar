rule TTP_XOR_WriteProcessMemory_a83b {
  strings:
    $key_a83b = { ff 49 [2] cd 6b [2] cb 5e [2] e5 5e [2] da 42 }

  condition:
    any of them
}