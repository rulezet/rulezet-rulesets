rule TTP_XOR_WriteProcessMemory_a867 {
  strings:
    $key_a867 = { ff 15 [2] cd 37 [2] cb 02 [2] e5 02 [2] da 1e }

  condition:
    any of them
}