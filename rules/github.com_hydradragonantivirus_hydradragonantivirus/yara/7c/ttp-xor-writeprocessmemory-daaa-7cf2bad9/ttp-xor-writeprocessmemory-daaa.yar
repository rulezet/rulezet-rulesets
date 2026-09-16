rule TTP_XOR_WriteProcessMemory_daaa {
  strings:
    $key_daaa = { 8d d8 [2] bf fa [2] b9 cf [2] 97 cf [2] a8 d3 }

  condition:
    any of them
}