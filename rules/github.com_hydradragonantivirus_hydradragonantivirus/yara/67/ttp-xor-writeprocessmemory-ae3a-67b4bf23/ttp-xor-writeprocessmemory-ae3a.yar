rule TTP_XOR_WriteProcessMemory_ae3a {
  strings:
    $key_ae3a = { f9 48 [2] cb 6a [2] cd 5f [2] e3 5f [2] dc 43 }

  condition:
    any of them
}