rule TTP_XOR_WriteProcessMemory_3faa {
  strings:
    $key_3faa = { 68 d8 [2] 5a fa [2] 5c cf [2] 72 cf [2] 4d d3 }

  condition:
    any of them
}