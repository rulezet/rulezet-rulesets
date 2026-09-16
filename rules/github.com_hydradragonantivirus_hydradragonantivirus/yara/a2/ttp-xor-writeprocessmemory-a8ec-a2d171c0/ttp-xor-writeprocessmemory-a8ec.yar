rule TTP_XOR_WriteProcessMemory_a8ec {
  strings:
    $key_a8ec = { ff 9e [2] cd bc [2] cb 89 [2] e5 89 [2] da 95 }

  condition:
    any of them
}