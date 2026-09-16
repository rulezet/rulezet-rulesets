rule TTP_XOR_WriteProcessMemory_ae9b {
  strings:
    $key_ae9b = { f9 e9 [2] cb cb [2] cd fe [2] e3 fe [2] dc e2 }

  condition:
    any of them
}