rule TTP_XOR_WriteProcessMemory_a817 {
  strings:
    $key_a817 = { ff 65 [2] cd 47 [2] cb 72 [2] e5 72 [2] da 6e }

  condition:
    any of them
}