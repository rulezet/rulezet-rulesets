rule TTP_XOR_WriteProcessMemory_aecc {
  strings:
    $key_aecc = { f9 be [2] cb 9c [2] cd a9 [2] e3 a9 [2] dc b5 }

  condition:
    any of them
}