rule TTP_XOR_WriteProcessMemory_a878 {
  strings:
    $key_a878 = { ff 0a [2] cd 28 [2] cb 1d [2] e5 1d [2] da 01 }

  condition:
    any of them
}