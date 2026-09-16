rule TTP_XOR_WriteProcessMemory_24aa {
  strings:
    $key_24aa = { 73 d8 [2] 41 fa [2] 47 cf [2] 69 cf [2] 56 d3 }

  condition:
    any of them
}