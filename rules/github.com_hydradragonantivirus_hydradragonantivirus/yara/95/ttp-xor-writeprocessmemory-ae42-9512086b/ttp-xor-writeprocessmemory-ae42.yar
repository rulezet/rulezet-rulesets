rule TTP_XOR_WriteProcessMemory_ae42 {
  strings:
    $key_ae42 = { f9 30 [2] cb 12 [2] cd 27 [2] e3 27 [2] dc 3b }

  condition:
    any of them
}