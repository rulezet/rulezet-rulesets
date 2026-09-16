rule TTP_XOR_WriteProcessMemory_0eaa {
  strings:
    $key_0eaa = { 59 d8 [2] 6b fa [2] 6d cf [2] 43 cf [2] 7c d3 }

  condition:
    any of them
}