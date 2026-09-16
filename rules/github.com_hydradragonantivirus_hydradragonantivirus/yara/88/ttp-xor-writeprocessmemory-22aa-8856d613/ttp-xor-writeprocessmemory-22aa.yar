rule TTP_XOR_WriteProcessMemory_22aa {
  strings:
    $key_22aa = { 75 d8 [2] 47 fa [2] 41 cf [2] 6f cf [2] 50 d3 }

  condition:
    any of them
}