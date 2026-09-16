rule TTP_XOR_WriteProcessMemory_ae3f {
  strings:
    $key_ae3f = { f9 4d [2] cb 6f [2] cd 5a [2] e3 5a [2] dc 46 }

  condition:
    any of them
}