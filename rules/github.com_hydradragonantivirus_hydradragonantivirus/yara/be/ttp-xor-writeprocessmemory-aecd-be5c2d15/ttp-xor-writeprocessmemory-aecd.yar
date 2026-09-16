rule TTP_XOR_WriteProcessMemory_aecd {
  strings:
    $key_aecd = { f9 bf [2] cb 9d [2] cd a8 [2] e3 a8 [2] dc b4 }

  condition:
    any of them
}