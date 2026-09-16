rule TTP_XOR_WriteProcessMemory_ffaa {
  strings:
    $key_ffaa = { a8 d8 [2] 9a fa [2] 9c cf [2] b2 cf [2] 8d d3 }

  condition:
    any of them
}