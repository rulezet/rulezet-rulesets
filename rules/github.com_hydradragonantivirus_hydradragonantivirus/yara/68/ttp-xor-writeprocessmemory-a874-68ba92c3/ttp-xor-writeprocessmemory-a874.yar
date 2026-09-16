rule TTP_XOR_WriteProcessMemory_a874 {
  strings:
    $key_a874 = { ff 06 [2] cd 24 [2] cb 11 [2] e5 11 [2] da 0d }

  condition:
    any of them
}