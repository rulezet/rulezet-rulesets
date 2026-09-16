rule TTP_XOR_WriteProcessMemory_5aaa {
  strings:
    $key_5aaa = { 0d d8 [2] 3f fa [2] 39 cf [2] 17 cf [2] 28 d3 }

  condition:
    any of them
}