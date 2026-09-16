rule TTP_XOR_WriteProcessMemory_a8d8 {
  strings:
    $key_a8d8 = { ff aa [2] cd 88 [2] cb bd [2] e5 bd [2] da a1 }

  condition:
    any of them
}