rule TTP_XOR_WriteProcessMemory_ae98 {
  strings:
    $key_ae98 = { f9 ea [2] cb c8 [2] cd fd [2] e3 fd [2] dc e1 }

  condition:
    any of them
}