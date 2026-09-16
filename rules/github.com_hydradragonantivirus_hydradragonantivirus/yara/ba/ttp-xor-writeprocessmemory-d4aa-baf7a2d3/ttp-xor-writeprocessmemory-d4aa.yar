rule TTP_XOR_WriteProcessMemory_d4aa {
  strings:
    $key_d4aa = { 83 d8 [2] b1 fa [2] b7 cf [2] 99 cf [2] a6 d3 }

  condition:
    any of them
}