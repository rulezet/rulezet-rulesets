rule TTP_XOR_WriteProcessMemory_a87c {
  strings:
    $key_a87c = { ff 0e [2] cd 2c [2] cb 19 [2] e5 19 [2] da 05 }

  condition:
    any of them
}