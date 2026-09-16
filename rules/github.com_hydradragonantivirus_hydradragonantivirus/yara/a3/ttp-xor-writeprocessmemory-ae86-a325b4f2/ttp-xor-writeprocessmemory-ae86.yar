rule TTP_XOR_WriteProcessMemory_ae86 {
  strings:
    $key_ae86 = { f9 f4 [2] cb d6 [2] cd e3 [2] e3 e3 [2] dc ff }

  condition:
    any of them
}