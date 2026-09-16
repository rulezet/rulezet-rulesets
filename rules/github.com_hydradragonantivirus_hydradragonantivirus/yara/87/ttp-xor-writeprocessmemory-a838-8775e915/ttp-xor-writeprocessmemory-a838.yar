rule TTP_XOR_WriteProcessMemory_a838 {
  strings:
    $key_a838 = { ff 4a [2] cd 68 [2] cb 5d [2] e5 5d [2] da 41 }

  condition:
    any of them
}