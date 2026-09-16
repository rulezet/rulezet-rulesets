rule TTP_XOR_WriteProcessMemory_a5aa {
  strings:
    $key_a5aa = { f2 d8 [2] c0 fa [2] c6 cf [2] e8 cf [2] d7 d3 }

  condition:
    any of them
}