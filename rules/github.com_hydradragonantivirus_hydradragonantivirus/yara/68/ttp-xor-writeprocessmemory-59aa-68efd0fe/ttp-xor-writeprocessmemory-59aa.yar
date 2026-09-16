rule TTP_XOR_WriteProcessMemory_59aa {
  strings:
    $key_59aa = { 0e d8 [2] 3c fa [2] 3a cf [2] 14 cf [2] 2b d3 }

  condition:
    any of them
}