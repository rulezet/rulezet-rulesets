rule TTP_XOR_WriteProcessMemory_b6a2 {
  strings:
    $key_b6a2 = { e1 d0 [2] d3 f2 [2] d5 c7 [2] fb c7 [2] c4 db }

  condition:
    any of them
}