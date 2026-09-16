rule TTP_XOR_WriteProcessMemory_a8c0 {
  strings:
    $key_a8c0 = { ff b2 [2] cd 90 [2] cb a5 [2] e5 a5 [2] da b9 }

  condition:
    any of them
}