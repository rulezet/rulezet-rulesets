rule TTP_XOR_WriteProcessMemory_ae15 {
  strings:
    $key_ae15 = { f9 67 [2] cb 45 [2] cd 70 [2] e3 70 [2] dc 6c }

  condition:
    any of them
}