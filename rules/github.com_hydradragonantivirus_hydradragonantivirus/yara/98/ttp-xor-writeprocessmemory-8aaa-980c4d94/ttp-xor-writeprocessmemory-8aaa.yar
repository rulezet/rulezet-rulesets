rule TTP_XOR_WriteProcessMemory_8aaa {
  strings:
    $key_8aaa = { dd d8 [2] ef fa [2] e9 cf [2] c7 cf [2] f8 d3 }

  condition:
    any of them
}