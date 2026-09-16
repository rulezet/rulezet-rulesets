rule TTP_XOR_WriteProcessMemory_54aa {
  strings:
    $key_54aa = { 03 d8 [2] 31 fa [2] 37 cf [2] 19 cf [2] 26 d3 }

  condition:
    any of them
}