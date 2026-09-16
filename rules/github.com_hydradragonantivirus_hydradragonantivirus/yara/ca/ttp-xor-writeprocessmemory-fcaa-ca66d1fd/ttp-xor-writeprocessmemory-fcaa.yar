rule TTP_XOR_WriteProcessMemory_fcaa {
  strings:
    $key_fcaa = { ab d8 [2] 99 fa [2] 9f cf [2] b1 cf [2] 8e d3 }

  condition:
    any of them
}