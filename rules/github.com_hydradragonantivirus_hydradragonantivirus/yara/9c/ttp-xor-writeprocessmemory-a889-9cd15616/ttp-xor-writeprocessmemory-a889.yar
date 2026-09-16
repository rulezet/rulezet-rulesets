rule TTP_XOR_WriteProcessMemory_a889 {
  strings:
    $key_a889 = { ff fb [2] cd d9 [2] cb ec [2] e5 ec [2] da f0 }

  condition:
    any of them
}