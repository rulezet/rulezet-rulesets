rule TTP_XOR_WriteProcessMemory_a87a {
  strings:
    $key_a87a = { ff 08 [2] cd 2a [2] cb 1f [2] e5 1f [2] da 03 }

  condition:
    any of them
}