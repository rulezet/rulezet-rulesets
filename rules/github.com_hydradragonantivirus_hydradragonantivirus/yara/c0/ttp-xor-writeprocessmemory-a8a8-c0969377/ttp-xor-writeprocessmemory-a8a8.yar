rule TTP_XOR_WriteProcessMemory_a8a8 {
  strings:
    $key_a8a8 = { ff da [2] cd f8 [2] cb cd [2] e5 cd [2] da d1 }

  condition:
    any of them
}