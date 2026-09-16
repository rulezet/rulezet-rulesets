rule TTP_XOR_WriteProcessMemory_92aa {
  strings:
    $key_92aa = { c5 d8 [2] f7 fa [2] f1 cf [2] df cf [2] e0 d3 }

  condition:
    any of them
}