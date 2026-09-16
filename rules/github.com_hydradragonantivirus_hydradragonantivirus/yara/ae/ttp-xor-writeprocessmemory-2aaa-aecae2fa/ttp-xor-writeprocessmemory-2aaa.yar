rule TTP_XOR_WriteProcessMemory_2aaa {
  strings:
    $key_2aaa = { 7d d8 [2] 4f fa [2] 49 cf [2] 67 cf [2] 58 d3 }

  condition:
    any of them
}