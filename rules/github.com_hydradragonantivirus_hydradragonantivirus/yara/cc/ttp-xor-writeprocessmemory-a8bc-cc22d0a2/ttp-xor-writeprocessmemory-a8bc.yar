rule TTP_XOR_WriteProcessMemory_a8bc {
  strings:
    $key_a8bc = { ff ce [2] cd ec [2] cb d9 [2] e5 d9 [2] da c5 }

  condition:
    any of them
}