rule TTP_XOR_WriteProcessMemory_a892 {
  strings:
    $key_a892 = { ff e0 [2] cd c2 [2] cb f7 [2] e5 f7 [2] da eb }

  condition:
    any of them
}