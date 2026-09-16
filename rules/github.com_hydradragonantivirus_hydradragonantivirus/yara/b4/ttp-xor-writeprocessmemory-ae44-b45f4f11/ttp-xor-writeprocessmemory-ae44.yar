rule TTP_XOR_WriteProcessMemory_ae44 {
  strings:
    $key_ae44 = { f9 36 [2] cb 14 [2] cd 21 [2] e3 21 [2] dc 3d }

  condition:
    any of them
}