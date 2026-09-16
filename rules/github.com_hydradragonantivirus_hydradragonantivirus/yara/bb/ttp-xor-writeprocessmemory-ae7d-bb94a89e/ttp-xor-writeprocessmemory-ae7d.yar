rule TTP_XOR_WriteProcessMemory_ae7d {
  strings:
    $key_ae7d = { f9 0f [2] cb 2d [2] cd 18 [2] e3 18 [2] dc 04 }

  condition:
    any of them
}