rule TTP_XOR_WriteProcessMemory_15aa {
  strings:
    $key_15aa = { 42 d8 [2] 70 fa [2] 76 cf [2] 58 cf [2] 67 d3 }

  condition:
    any of them
}