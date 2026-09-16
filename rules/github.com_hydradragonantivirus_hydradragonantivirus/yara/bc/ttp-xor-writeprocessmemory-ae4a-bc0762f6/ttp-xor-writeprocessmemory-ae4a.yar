rule TTP_XOR_WriteProcessMemory_ae4a {
  strings:
    $key_ae4a = { f9 38 [2] cb 1a [2] cd 2f [2] e3 2f [2] dc 33 }

  condition:
    any of them
}