rule TTP_XOR_WriteProcessMemory_74aa {
  strings:
    $key_74aa = { 23 d8 [2] 11 fa [2] 17 cf [2] 39 cf [2] 06 d3 }

  condition:
    any of them
}