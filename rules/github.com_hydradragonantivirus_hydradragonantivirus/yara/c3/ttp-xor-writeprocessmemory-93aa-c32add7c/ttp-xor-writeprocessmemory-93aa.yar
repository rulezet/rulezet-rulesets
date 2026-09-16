rule TTP_XOR_WriteProcessMemory_93aa {
  strings:
    $key_93aa = { c4 d8 [2] f6 fa [2] f0 cf [2] de cf [2] e1 d3 }

  condition:
    any of them
}