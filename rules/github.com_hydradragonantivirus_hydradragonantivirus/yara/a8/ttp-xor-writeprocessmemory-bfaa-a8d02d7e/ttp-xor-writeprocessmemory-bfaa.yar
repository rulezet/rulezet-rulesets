rule TTP_XOR_WriteProcessMemory_bfaa {
  strings:
    $key_bfaa = { e8 d8 [2] da fa [2] dc cf [2] f2 cf [2] cd d3 }

  condition:
    any of them
}