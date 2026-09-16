rule TTP_XOR_WriteProcessMemory_4daa {
  strings:
    $key_4daa = { 1a d8 [2] 28 fa [2] 2e cf [2] 00 cf [2] 3f d3 }

  condition:
    any of them
}