rule TTP_XOR_WriteProcessMemory_e8aa {
  strings:
    $key_e8aa = { bf d8 [2] 8d fa [2] 8b cf [2] a5 cf [2] 9a d3 }

  condition:
    any of them
}