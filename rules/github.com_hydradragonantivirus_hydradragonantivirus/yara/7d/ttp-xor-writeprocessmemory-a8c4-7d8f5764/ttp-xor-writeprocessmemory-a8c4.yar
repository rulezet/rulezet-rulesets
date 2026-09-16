rule TTP_XOR_WriteProcessMemory_a8c4 {
  strings:
    $key_a8c4 = { ff b6 [2] cd 94 [2] cb a1 [2] e5 a1 [2] da bd }

  condition:
    any of them
}