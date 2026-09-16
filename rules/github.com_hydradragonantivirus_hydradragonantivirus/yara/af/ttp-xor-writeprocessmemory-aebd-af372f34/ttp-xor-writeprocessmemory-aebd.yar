rule TTP_XOR_WriteProcessMemory_aebd {
  strings:
    $key_aebd = { f9 cf [2] cb ed [2] cd d8 [2] e3 d8 [2] dc c4 }

  condition:
    any of them
}