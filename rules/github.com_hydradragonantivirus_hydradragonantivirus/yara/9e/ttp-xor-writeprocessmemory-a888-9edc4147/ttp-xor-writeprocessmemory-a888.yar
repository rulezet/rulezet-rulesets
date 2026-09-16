rule TTP_XOR_WriteProcessMemory_a888 {
  strings:
    $key_a888 = { ff fa [2] cd d8 [2] cb ed [2] e5 ed [2] da f1 }

  condition:
    any of them
}