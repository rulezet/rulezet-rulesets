rule TTP_XOR_WriteProcessMemory_1faa {
  strings:
    $key_1faa = { 48 d8 [2] 7a fa [2] 7c cf [2] 52 cf [2] 6d d3 }

  condition:
    any of them
}