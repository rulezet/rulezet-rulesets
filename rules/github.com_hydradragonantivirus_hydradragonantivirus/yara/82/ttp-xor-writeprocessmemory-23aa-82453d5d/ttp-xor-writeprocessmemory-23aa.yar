rule TTP_XOR_WriteProcessMemory_23aa {
  strings:
    $key_23aa = { 74 d8 [2] 46 fa [2] 40 cf [2] 6e cf [2] 51 d3 }

  condition:
    any of them
}