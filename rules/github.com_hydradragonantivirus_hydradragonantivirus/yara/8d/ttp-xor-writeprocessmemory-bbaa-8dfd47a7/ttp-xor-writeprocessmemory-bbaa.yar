rule TTP_XOR_WriteProcessMemory_bbaa {
  strings:
    $key_bbaa = { ec d8 [2] de fa [2] d8 cf [2] f6 cf [2] c9 d3 }

  condition:
    any of them
}