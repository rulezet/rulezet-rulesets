rule TTP_XOR_WriteProcessMemory_a857 {
  strings:
    $key_a857 = { ff 25 [2] cd 07 [2] cb 32 [2] e5 32 [2] da 2e }

  condition:
    any of them
}