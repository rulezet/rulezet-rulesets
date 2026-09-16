rule TTP_XOR_WriteProcessMemory_a837 {
  strings:
    $key_a837 = { ff 45 [2] cd 67 [2] cb 52 [2] e5 52 [2] da 4e }

  condition:
    any of them
}