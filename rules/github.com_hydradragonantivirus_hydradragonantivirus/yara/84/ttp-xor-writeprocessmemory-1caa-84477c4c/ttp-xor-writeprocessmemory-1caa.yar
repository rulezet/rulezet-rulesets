rule TTP_XOR_WriteProcessMemory_1caa {
  strings:
    $key_1caa = { 4b d8 [2] 79 fa [2] 7f cf [2] 51 cf [2] 6e d3 }

  condition:
    any of them
}