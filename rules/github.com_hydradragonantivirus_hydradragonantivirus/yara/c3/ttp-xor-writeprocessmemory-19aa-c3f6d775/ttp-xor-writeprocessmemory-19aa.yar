rule TTP_XOR_WriteProcessMemory_19aa {
  strings:
    $key_19aa = { 4e d8 [2] 7c fa [2] 7a cf [2] 54 cf [2] 6b d3 }

  condition:
    any of them
}