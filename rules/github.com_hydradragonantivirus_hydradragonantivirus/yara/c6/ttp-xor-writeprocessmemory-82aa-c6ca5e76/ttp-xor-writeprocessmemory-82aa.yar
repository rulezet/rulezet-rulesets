rule TTP_XOR_WriteProcessMemory_82aa {
  strings:
    $key_82aa = { d5 d8 [2] e7 fa [2] e1 cf [2] cf cf [2] f0 d3 }

  condition:
    any of them
}