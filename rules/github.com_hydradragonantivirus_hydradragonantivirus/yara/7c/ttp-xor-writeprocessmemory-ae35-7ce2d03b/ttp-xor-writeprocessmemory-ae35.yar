rule TTP_XOR_WriteProcessMemory_ae35 {
  strings:
    $key_ae35 = { f9 47 [2] cb 65 [2] cd 50 [2] e3 50 [2] dc 4c }

  condition:
    any of them
}