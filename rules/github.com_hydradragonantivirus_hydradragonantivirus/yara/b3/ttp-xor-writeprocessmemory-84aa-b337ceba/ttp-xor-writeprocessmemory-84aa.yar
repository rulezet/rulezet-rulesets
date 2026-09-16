rule TTP_XOR_WriteProcessMemory_84aa {
  strings:
    $key_84aa = { d3 d8 [2] e1 fa [2] e7 cf [2] c9 cf [2] f6 d3 }

  condition:
    any of them
}