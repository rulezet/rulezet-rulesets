rule TTP_XOR_WriteProcessMemory_adaa {
  strings:
    $key_adaa = { fa d8 [2] c8 fa [2] ce cf [2] e0 cf [2] df d3 }

  condition:
    any of them
}