rule TTP_XOR_WriteProcessMemory_17aa {
  strings:
    $key_17aa = { 40 d8 [2] 72 fa [2] 74 cf [2] 5a cf [2] 65 d3 }

  condition:
    any of them
}