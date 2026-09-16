rule TTP_XOR_WriteProcessMemory_ae95 {
  strings:
    $key_ae95 = { f9 e7 [2] cb c5 [2] cd f0 [2] e3 f0 [2] dc ec }

  condition:
    any of them
}