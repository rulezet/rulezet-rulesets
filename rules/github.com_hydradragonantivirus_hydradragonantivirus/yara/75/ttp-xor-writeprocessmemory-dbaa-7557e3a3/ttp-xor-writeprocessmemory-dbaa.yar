rule TTP_XOR_WriteProcessMemory_dbaa {
  strings:
    $key_dbaa = { 8c d8 [2] be fa [2] b8 cf [2] 96 cf [2] a9 d3 }

  condition:
    any of them
}