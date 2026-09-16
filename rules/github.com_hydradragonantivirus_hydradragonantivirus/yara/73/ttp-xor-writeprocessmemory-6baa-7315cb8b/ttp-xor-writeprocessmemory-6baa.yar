rule TTP_XOR_WriteProcessMemory_6baa {
  strings:
    $key_6baa = { 3c d8 [2] 0e fa [2] 08 cf [2] 26 cf [2] 19 d3 }

  condition:
    any of them
}