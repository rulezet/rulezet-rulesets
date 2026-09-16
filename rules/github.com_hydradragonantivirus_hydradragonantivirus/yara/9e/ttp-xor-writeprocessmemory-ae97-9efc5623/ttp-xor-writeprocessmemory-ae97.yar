rule TTP_XOR_WriteProcessMemory_ae97 {
  strings:
    $key_ae97 = { f9 e5 [2] cb c7 [2] cd f2 [2] e3 f2 [2] dc ee }

  condition:
    any of them
}