rule TTP_XOR_WriteProcessMemory_66aa {
  strings:
    $key_66aa = { 31 d8 [2] 03 fa [2] 05 cf [2] 2b cf [2] 14 d3 }

  condition:
    any of them
}