rule TTP_XOR_WriteProcessMemory_ae3d {
  strings:
    $key_ae3d = { f9 4f [2] cb 6d [2] cd 58 [2] e3 58 [2] dc 44 }

  condition:
    any of them
}