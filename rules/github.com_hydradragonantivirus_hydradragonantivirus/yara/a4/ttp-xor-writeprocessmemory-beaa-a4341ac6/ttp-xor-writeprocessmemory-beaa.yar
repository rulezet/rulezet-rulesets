rule TTP_XOR_WriteProcessMemory_beaa {
  strings:
    $key_beaa = { e9 d8 [2] db fa [2] dd cf [2] f3 cf [2] cc d3 }

  condition:
    any of them
}