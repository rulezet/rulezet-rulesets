rule TTP_XOR_WriteProcessMemory_01aa {
  strings:
    $key_01aa = { 56 d8 [2] 64 fa [2] 62 cf [2] 4c cf [2] 73 d3 }

  condition:
    any of them
}