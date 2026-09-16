rule TTP_XOR_WriteProcessMemory_aed2 {
  strings:
    $key_aed2 = { f9 a0 [2] cb 82 [2] cd b7 [2] e3 b7 [2] dc ab }

  condition:
    any of them
}