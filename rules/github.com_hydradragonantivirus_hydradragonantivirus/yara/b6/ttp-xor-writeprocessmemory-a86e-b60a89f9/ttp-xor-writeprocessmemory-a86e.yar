rule TTP_XOR_WriteProcessMemory_a86e {
  strings:
    $key_a86e = { ff 1c [2] cd 3e [2] cb 0b [2] e5 0b [2] da 17 }

  condition:
    any of them
}