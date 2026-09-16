rule TTP_XOR_WriteProcessMemory_ae83 {
  strings:
    $key_ae83 = { f9 f1 [2] cb d3 [2] cd e6 [2] e3 e6 [2] dc fa }

  condition:
    any of them
}