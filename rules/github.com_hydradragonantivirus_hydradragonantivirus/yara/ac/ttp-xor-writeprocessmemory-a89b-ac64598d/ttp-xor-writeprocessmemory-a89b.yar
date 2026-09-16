rule TTP_XOR_WriteProcessMemory_a89b {
  strings:
    $key_a89b = { ff e9 [2] cd cb [2] cb fe [2] e5 fe [2] da e2 }

  condition:
    any of them
}