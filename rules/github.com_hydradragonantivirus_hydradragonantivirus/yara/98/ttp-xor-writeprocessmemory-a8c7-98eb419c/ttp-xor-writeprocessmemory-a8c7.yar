rule TTP_XOR_WriteProcessMemory_a8c7 {
  strings:
    $key_a8c7 = { ff b5 [2] cd 97 [2] cb a2 [2] e5 a2 [2] da be }

  condition:
    any of them
}