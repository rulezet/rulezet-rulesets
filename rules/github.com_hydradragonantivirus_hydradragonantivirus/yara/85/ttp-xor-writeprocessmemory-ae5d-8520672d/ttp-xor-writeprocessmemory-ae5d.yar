rule TTP_XOR_WriteProcessMemory_ae5d {
  strings:
    $key_ae5d = { f9 2f [2] cb 0d [2] cd 38 [2] e3 38 [2] dc 24 }

  condition:
    any of them
}