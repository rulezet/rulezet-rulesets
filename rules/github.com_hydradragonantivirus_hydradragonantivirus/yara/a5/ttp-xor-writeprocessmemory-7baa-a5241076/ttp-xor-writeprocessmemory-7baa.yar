rule TTP_XOR_WriteProcessMemory_7baa {
  strings:
    $key_7baa = { 2c d8 [2] 1e fa [2] 18 cf [2] 36 cf [2] 09 d3 }

  condition:
    any of them
}