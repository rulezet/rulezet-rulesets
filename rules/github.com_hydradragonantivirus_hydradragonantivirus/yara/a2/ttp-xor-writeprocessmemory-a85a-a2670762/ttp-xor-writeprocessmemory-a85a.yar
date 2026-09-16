rule TTP_XOR_WriteProcessMemory_a85a {
  strings:
    $key_a85a = { ff 28 [2] cd 0a [2] cb 3f [2] e5 3f [2] da 23 }

  condition:
    any of them
}