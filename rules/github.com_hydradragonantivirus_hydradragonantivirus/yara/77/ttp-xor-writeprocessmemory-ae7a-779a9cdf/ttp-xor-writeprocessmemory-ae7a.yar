rule TTP_XOR_WriteProcessMemory_ae7a {
  strings:
    $key_ae7a = { f9 08 [2] cb 2a [2] cd 1f [2] e3 1f [2] dc 03 }

  condition:
    any of them
}