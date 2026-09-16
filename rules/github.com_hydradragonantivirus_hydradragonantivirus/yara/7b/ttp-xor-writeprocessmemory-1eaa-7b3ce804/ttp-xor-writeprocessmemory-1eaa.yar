rule TTP_XOR_WriteProcessMemory_1eaa {
  strings:
    $key_1eaa = { 49 d8 [2] 7b fa [2] 7d cf [2] 53 cf [2] 6c d3 }

  condition:
    any of them
}