rule TTP_XOR_WriteProcessMemory_28aa {
  strings:
    $key_28aa = { 7f d8 [2] 4d fa [2] 4b cf [2] 65 cf [2] 5a d3 }

  condition:
    any of them
}