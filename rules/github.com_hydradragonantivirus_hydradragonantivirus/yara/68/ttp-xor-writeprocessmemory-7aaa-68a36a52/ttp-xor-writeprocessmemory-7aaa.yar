rule TTP_XOR_WriteProcessMemory_7aaa {
  strings:
    $key_7aaa = { 2d d8 [2] 1f fa [2] 19 cf [2] 37 cf [2] 08 d3 }

  condition:
    any of them
}