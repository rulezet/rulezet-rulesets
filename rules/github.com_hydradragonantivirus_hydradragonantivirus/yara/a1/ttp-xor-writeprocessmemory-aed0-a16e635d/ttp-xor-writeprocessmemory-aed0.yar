rule TTP_XOR_WriteProcessMemory_aed0 {
  strings:
    $key_aed0 = { f9 a2 [2] cb 80 [2] cd b5 [2] e3 b5 [2] dc a9 }

  condition:
    any of them
}