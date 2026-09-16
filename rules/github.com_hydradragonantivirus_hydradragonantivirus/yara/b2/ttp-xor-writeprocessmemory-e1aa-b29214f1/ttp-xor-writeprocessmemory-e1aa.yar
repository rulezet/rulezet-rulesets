rule TTP_XOR_WriteProcessMemory_e1aa {
  strings:
    $key_e1aa = { b6 d8 [2] 84 fa [2] 82 cf [2] ac cf [2] 93 d3 }

  condition:
    any of them
}