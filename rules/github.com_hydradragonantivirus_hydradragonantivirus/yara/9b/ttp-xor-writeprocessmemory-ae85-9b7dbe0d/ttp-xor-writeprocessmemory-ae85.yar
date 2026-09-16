rule TTP_XOR_WriteProcessMemory_ae85 {
  strings:
    $key_ae85 = { f9 f7 [2] cb d5 [2] cd e0 [2] e3 e0 [2] dc fc }

  condition:
    any of them
}