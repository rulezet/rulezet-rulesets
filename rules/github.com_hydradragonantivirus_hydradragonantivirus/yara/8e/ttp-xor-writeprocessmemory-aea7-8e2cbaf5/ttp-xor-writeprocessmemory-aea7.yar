rule TTP_XOR_WriteProcessMemory_aea7 {
  strings:
    $key_aea7 = { f9 d5 [2] cb f7 [2] cd c2 [2] e3 c2 [2] dc de }

  condition:
    any of them
}