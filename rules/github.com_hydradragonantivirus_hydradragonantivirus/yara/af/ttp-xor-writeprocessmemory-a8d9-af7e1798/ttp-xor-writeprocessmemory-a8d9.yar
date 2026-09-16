rule TTP_XOR_WriteProcessMemory_a8d9 {
  strings:
    $key_a8d9 = { ff ab [2] cd 89 [2] cb bc [2] e5 bc [2] da a0 }

  condition:
    any of them
}