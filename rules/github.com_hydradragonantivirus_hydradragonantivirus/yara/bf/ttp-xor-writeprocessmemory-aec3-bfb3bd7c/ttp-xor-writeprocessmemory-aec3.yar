rule TTP_XOR_WriteProcessMemory_aec3 {
  strings:
    $key_aec3 = { f9 b1 [2] cb 93 [2] cd a6 [2] e3 a6 [2] dc ba }

  condition:
    any of them
}