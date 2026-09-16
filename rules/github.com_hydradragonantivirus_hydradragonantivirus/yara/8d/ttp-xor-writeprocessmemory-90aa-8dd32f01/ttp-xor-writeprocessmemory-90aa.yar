rule TTP_XOR_WriteProcessMemory_90aa {
  strings:
    $key_90aa = { c7 d8 [2] f5 fa [2] f3 cf [2] dd cf [2] e2 d3 }

  condition:
    any of them
}