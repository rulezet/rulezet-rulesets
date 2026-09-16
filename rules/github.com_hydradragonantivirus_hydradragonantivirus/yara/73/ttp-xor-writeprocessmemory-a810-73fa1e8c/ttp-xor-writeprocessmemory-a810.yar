rule TTP_XOR_WriteProcessMemory_a810 {
  strings:
    $key_a810 = { ff 62 [2] cd 40 [2] cb 75 [2] e5 75 [2] da 69 }

  condition:
    any of them
}