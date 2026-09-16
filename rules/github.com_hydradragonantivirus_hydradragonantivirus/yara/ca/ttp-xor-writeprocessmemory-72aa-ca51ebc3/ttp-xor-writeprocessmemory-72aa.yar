rule TTP_XOR_WriteProcessMemory_72aa {
  strings:
    $key_72aa = { 25 d8 [2] 17 fa [2] 11 cf [2] 3f cf [2] 00 d3 }

  condition:
    any of them
}