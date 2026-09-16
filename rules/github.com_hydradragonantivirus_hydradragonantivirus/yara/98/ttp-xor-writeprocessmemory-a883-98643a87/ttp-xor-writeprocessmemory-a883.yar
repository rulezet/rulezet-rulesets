rule TTP_XOR_WriteProcessMemory_a883 {
  strings:
    $key_a883 = { ff f1 [2] cd d3 [2] cb e6 [2] e5 e6 [2] da fa }

  condition:
    any of them
}