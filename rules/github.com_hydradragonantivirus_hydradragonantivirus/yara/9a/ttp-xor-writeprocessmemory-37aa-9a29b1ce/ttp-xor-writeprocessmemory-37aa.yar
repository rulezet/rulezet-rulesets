rule TTP_XOR_WriteProcessMemory_37aa {
  strings:
    $key_37aa = { 60 d8 [2] 52 fa [2] 54 cf [2] 7a cf [2] 45 d3 }

  condition:
    any of them
}