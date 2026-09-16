rule TTP_XOR_WriteProcessMemory_aebc {
  strings:
    $key_aebc = { f9 ce [2] cb ec [2] cd d9 [2] e3 d9 [2] dc c5 }

  condition:
    any of them
}