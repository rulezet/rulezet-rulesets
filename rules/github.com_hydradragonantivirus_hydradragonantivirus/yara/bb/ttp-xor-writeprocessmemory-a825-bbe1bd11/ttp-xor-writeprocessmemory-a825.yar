rule TTP_XOR_WriteProcessMemory_a825 {
  strings:
    $key_a825 = { ff 57 [2] cd 75 [2] cb 40 [2] e5 40 [2] da 5c }

  condition:
    any of them
}