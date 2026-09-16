rule TTP_XOR_WriteProcessMemory_8baa {
  strings:
    $key_8baa = { dc d8 [2] ee fa [2] e8 cf [2] c6 cf [2] f9 d3 }

  condition:
    any of them
}