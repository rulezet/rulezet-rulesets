rule TTP_XOR_WriteProcessMemory_a86f {
  strings:
    $key_a86f = { ff 1d [2] cd 3f [2] cb 0a [2] e5 0a [2] da 16 }

  condition:
    any of them
}