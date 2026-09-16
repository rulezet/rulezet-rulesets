rule TTP_XOR_WriteProcessMemory_a896 {
  strings:
    $key_a896 = { ff e4 [2] cd c6 [2] cb f3 [2] e5 f3 [2] da ef }

  condition:
    any of them
}