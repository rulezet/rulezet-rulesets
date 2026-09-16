rule TTP_XOR_WriteProcessMemory_ae9d {
  strings:
    $key_ae9d = { f9 ef [2] cb cd [2] cd f8 [2] e3 f8 [2] dc e4 }

  condition:
    any of them
}