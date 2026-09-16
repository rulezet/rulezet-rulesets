rule TTP_XOR_WriteProcessMemory_e4aa {
  strings:
    $key_e4aa = { b3 d8 [2] 81 fa [2] 87 cf [2] a9 cf [2] 96 d3 }

  condition:
    any of them
}