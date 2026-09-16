rule TTP_XOR_WriteProcessMemory_baaa {
  strings:
    $key_baaa = { ed d8 [2] df fa [2] d9 cf [2] f7 cf [2] c8 d3 }

  condition:
    any of them
}