rule TTP_XOR_WriteProcessMemory_aeb1 {
  strings:
    $key_aeb1 = { f9 c3 [2] cb e1 [2] cd d4 [2] e3 d4 [2] dc c8 }

  condition:
    any of them
}