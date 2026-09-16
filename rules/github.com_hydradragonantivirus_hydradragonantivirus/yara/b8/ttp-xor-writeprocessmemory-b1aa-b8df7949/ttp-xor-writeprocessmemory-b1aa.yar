rule TTP_XOR_WriteProcessMemory_b1aa {
  strings:
    $key_b1aa = { e6 d8 [2] d4 fa [2] d2 cf [2] fc cf [2] c3 d3 }

  condition:
    any of them
}