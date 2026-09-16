rule TTP_XOR_WriteProcessMemory_d6aa {
  strings:
    $key_d6aa = { 81 d8 [2] b3 fa [2] b5 cf [2] 9b cf [2] a4 d3 }

  condition:
    any of them
}