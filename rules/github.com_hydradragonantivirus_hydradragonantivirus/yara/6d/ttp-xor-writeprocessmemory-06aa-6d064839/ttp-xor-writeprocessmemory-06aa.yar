rule TTP_XOR_WriteProcessMemory_06aa {
  strings:
    $key_06aa = { 51 d8 [2] 63 fa [2] 65 cf [2] 4b cf [2] 74 d3 }

  condition:
    any of them
}