rule TTP_XOR_WriteProcessMemory_7daa {
  strings:
    $key_7daa = { 2a d8 [2] 18 fa [2] 1e cf [2] 30 cf [2] 0f d3 }

  condition:
    any of them
}