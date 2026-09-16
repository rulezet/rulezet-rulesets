rule TTP_XOR_WriteProcessMemory_ae9a {
  strings:
    $key_ae9a = { f9 e8 [2] cb ca [2] cd ff [2] e3 ff [2] dc e3 }

  condition:
    any of them
}