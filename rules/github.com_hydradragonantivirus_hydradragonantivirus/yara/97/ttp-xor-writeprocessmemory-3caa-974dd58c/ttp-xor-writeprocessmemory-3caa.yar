rule TTP_XOR_WriteProcessMemory_3caa {
  strings:
    $key_3caa = { 6b d8 [2] 59 fa [2] 5f cf [2] 71 cf [2] 4e d3 }

  condition:
    any of them
}