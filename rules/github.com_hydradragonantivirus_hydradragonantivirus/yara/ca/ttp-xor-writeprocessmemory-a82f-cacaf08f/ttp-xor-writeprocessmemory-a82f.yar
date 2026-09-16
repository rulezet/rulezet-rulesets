rule TTP_XOR_WriteProcessMemory_a82f {
  strings:
    $key_a82f = { ff 5d [2] cd 7f [2] cb 4a [2] e5 4a [2] da 56 }

  condition:
    any of them
}