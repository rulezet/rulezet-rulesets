rule TTP_XOR_WriteProcessMemory_4caa {
  strings:
    $key_4caa = { 1b d8 [2] 29 fa [2] 2f cf [2] 01 cf [2] 3e d3 }

  condition:
    any of them
}