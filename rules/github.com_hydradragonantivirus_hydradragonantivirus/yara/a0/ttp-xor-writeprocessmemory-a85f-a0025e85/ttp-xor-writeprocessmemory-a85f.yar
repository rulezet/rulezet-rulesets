rule TTP_XOR_WriteProcessMemory_a85f {
  strings:
    $key_a85f = { ff 2d [2] cd 0f [2] cb 3a [2] e5 3a [2] da 26 }

  condition:
    any of them
}