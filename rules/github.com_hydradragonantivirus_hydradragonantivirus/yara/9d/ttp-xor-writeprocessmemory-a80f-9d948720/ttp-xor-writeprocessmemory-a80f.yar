rule TTP_XOR_WriteProcessMemory_a80f {
  strings:
    $key_a80f = { ff 7d [2] cd 5f [2] cb 6a [2] e5 6a [2] da 76 }

  condition:
    any of them
}