rule TTP_XOR_WriteProcessMemory_6eaa {
  strings:
    $key_6eaa = { 39 d8 [2] 0b fa [2] 0d cf [2] 23 cf [2] 1c d3 }

  condition:
    any of them
}