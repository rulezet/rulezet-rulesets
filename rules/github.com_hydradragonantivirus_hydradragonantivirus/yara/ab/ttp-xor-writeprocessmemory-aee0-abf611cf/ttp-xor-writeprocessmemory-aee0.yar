rule TTP_XOR_WriteProcessMemory_aee0 {
  strings:
    $key_aee0 = { f9 92 [2] cb b0 [2] cd 85 [2] e3 85 [2] dc 99 }

  condition:
    any of them
}