rule TTP_XOR_WriteProcessMemory_a871 {
  strings:
    $key_a871 = { ff 03 [2] cd 21 [2] cb 14 [2] e5 14 [2] da 08 }

  condition:
    any of them
}