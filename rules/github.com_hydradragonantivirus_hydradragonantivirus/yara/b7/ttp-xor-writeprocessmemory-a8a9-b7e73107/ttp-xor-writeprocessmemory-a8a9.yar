rule TTP_XOR_WriteProcessMemory_a8a9 {
  strings:
    $key_a8a9 = { ff db [2] cd f9 [2] cb cc [2] e5 cc [2] da d0 }

  condition:
    any of them
}