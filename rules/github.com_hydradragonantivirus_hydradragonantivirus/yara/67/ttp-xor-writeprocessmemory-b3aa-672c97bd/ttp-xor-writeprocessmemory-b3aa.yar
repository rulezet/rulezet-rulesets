rule TTP_XOR_WriteProcessMemory_b3aa {
  strings:
    $key_b3aa = { e4 d8 [2] d6 fa [2] d0 cf [2] fe cf [2] c1 d3 }

  condition:
    any of them
}