rule TTP_XOR_WriteProcessMemory_a882 {
  strings:
    $key_a882 = { ff f0 [2] cd d2 [2] cb e7 [2] e5 e7 [2] da fb }

  condition:
    any of them
}