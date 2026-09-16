rule TTP_XOR_WriteProcessMemory_d7aa {
  strings:
    $key_d7aa = { 80 d8 [2] b2 fa [2] b4 cf [2] 9a cf [2] a5 d3 }

  condition:
    any of them
}