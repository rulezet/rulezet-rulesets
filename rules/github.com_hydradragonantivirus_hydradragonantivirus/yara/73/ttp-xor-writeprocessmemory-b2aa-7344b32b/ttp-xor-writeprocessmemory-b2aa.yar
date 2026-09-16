rule TTP_XOR_WriteProcessMemory_b2aa {
  strings:
    $key_b2aa = { e5 d8 [2] d7 fa [2] d1 cf [2] ff cf [2] c0 d3 }

  condition:
    any of them
}