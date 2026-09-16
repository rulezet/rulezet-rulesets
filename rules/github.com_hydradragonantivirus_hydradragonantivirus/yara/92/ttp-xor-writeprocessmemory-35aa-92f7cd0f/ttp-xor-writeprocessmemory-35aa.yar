rule TTP_XOR_WriteProcessMemory_35aa {
  strings:
    $key_35aa = { 62 d8 [2] 50 fa [2] 56 cf [2] 78 cf [2] 47 d3 }

  condition:
    any of them
}