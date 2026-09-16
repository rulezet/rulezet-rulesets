rule TTP_XOR_WriteProcessMemory_a887 {
  strings:
    $key_a887 = { ff f5 [2] cd d7 [2] cb e2 [2] e5 e2 [2] da fe }

  condition:
    any of them
}