rule TTP_XOR_WriteProcessMemory_7eaa {
  strings:
    $key_7eaa = { 29 d8 [2] 1b fa [2] 1d cf [2] 33 cf [2] 0c d3 }

  condition:
    any of them
}