rule TTP_XOR_WriteProcessMemory_a80d {
  strings:
    $key_a80d = { ff 7f [2] cd 5d [2] cb 68 [2] e5 68 [2] da 74 }

  condition:
    any of them
}