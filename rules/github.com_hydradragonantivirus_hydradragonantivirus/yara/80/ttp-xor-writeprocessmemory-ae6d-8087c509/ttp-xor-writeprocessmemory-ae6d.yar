rule TTP_XOR_WriteProcessMemory_ae6d {
  strings:
    $key_ae6d = { f9 1f [2] cb 3d [2] cd 08 [2] e3 08 [2] dc 14 }

  condition:
    any of them
}