rule TTP_XOR_WriteProcessMemory_acaa {
  strings:
    $key_acaa = { fb d8 [2] c9 fa [2] cf cf [2] e1 cf [2] de d3 }

  condition:
    any of them
}