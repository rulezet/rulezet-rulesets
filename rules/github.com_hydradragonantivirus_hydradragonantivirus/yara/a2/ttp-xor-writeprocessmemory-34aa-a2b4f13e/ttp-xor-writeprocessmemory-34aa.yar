rule TTP_XOR_WriteProcessMemory_34aa {
  strings:
    $key_34aa = { 63 d8 [2] 51 fa [2] 57 cf [2] 79 cf [2] 46 d3 }

  condition:
    any of them
}