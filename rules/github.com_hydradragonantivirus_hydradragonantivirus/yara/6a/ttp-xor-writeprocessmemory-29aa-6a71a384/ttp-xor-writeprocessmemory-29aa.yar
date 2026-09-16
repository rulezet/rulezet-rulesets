rule TTP_XOR_WriteProcessMemory_29aa {
  strings:
    $key_29aa = { 7e d8 [2] 4c fa [2] 4a cf [2] 64 cf [2] 5b d3 }

  condition:
    any of them
}