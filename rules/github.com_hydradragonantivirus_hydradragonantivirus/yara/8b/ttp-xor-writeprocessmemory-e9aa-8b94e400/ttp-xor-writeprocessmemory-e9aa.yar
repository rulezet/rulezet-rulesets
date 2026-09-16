rule TTP_XOR_WriteProcessMemory_e9aa {
  strings:
    $key_e9aa = { be d8 [2] 8c fa [2] 8a cf [2] a4 cf [2] 9b d3 }

  condition:
    any of them
}