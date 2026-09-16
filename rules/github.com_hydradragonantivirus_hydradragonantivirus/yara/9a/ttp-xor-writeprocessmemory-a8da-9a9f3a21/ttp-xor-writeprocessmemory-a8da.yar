rule TTP_XOR_WriteProcessMemory_a8da {
  strings:
    $key_a8da = { ff a8 [2] cd 8a [2] cb bf [2] e5 bf [2] da a3 }

  condition:
    any of them
}