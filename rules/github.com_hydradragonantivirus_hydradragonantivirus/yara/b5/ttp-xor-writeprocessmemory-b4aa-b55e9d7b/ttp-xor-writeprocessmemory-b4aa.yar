rule TTP_XOR_WriteProcessMemory_b4aa {
  strings:
    $key_b4aa = { e3 d8 [2] d1 fa [2] d7 cf [2] f9 cf [2] c6 d3 }

  condition:
    any of them
}