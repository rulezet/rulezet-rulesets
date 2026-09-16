rule TTP_XOR_WriteProcessMemory_36aa {
  strings:
    $key_36aa = { 61 d8 [2] 53 fa [2] 55 cf [2] 7b cf [2] 44 d3 }

  condition:
    any of them
}