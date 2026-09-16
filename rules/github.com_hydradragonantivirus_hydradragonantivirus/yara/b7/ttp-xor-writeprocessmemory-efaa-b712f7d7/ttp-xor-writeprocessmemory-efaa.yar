rule TTP_XOR_WriteProcessMemory_efaa {
  strings:
    $key_efaa = { b8 d8 [2] 8a fa [2] 8c cf [2] a2 cf [2] 9d d3 }

  condition:
    any of them
}