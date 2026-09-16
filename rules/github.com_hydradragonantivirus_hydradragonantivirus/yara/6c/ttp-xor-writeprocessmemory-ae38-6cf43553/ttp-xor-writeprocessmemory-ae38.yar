rule TTP_XOR_WriteProcessMemory_ae38 {
  strings:
    $key_ae38 = { f9 4a [2] cb 68 [2] cd 5d [2] e3 5d [2] dc 41 }

  condition:
    any of them
}