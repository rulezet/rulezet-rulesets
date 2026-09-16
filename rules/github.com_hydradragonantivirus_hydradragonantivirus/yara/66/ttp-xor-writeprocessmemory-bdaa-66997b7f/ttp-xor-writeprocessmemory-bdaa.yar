rule TTP_XOR_WriteProcessMemory_bdaa {
  strings:
    $key_bdaa = { ea d8 [2] d8 fa [2] de cf [2] f0 cf [2] cf d3 }

  condition:
    any of them
}