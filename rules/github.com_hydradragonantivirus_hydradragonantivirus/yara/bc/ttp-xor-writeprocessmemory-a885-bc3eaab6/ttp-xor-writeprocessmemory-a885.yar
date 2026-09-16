rule TTP_XOR_WriteProcessMemory_a885 {
  strings:
    $key_a885 = { ff f7 [2] cd d5 [2] cb e0 [2] e5 e0 [2] da fc }

  condition:
    any of them
}