rule TTP_XOR_WriteProcessMemory_a81a {
  strings:
    $key_a81a = { ff 68 [2] cd 4a [2] cb 7f [2] e5 7f [2] da 63 }

  condition:
    any of them
}