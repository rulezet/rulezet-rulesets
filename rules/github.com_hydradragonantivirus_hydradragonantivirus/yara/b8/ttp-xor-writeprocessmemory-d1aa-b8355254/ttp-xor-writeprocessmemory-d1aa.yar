rule TTP_XOR_WriteProcessMemory_d1aa {
  strings:
    $key_d1aa = { 86 d8 [2] b4 fa [2] b2 cf [2] 9c cf [2] a3 d3 }

  condition:
    any of them
}