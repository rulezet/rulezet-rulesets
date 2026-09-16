rule TTP_XOR_WriteProcessMemory_78aa {
  strings:
    $key_78aa = { 2f d8 [2] 1d fa [2] 1b cf [2] 35 cf [2] 0a d3 }

  condition:
    any of them
}