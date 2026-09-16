rule TTP_XOR_WriteProcessMemory_a886 {
  strings:
    $key_a886 = { ff f4 [2] cd d6 [2] cb e3 [2] e5 e3 [2] da ff }

  condition:
    any of them
}