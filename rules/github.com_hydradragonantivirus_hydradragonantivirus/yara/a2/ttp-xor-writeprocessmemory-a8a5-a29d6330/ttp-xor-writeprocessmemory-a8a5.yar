rule TTP_XOR_WriteProcessMemory_a8a5 {
  strings:
    $key_a8a5 = { ff d7 [2] cd f5 [2] cb c0 [2] e5 c0 [2] da dc }

  condition:
    any of them
}