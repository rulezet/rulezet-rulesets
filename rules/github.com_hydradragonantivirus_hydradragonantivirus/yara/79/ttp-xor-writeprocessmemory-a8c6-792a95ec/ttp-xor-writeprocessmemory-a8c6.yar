rule TTP_XOR_WriteProcessMemory_a8c6 {
  strings:
    $key_a8c6 = { ff b4 [2] cd 96 [2] cb a3 [2] e5 a3 [2] da bf }

  condition:
    any of them
}