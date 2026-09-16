rule TTP_XOR_WriteProcessMemory_77aa {
  strings:
    $key_77aa = { 20 d8 [2] 12 fa [2] 14 cf [2] 3a cf [2] 05 d3 }

  condition:
    any of them
}