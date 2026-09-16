rule TTP_XOR_WriteProcessMemory_60aa {
  strings:
    $key_60aa = { 37 d8 [2] 05 fa [2] 03 cf [2] 2d cf [2] 12 d3 }

  condition:
    any of them
}