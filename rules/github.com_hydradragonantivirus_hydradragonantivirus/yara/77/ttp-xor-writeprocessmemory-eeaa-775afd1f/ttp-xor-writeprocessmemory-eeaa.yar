rule TTP_XOR_WriteProcessMemory_eeaa {
  strings:
    $key_eeaa = { b9 d8 [2] 8b fa [2] 8d cf [2] a3 cf [2] 9c d3 }

  condition:
    any of them
}