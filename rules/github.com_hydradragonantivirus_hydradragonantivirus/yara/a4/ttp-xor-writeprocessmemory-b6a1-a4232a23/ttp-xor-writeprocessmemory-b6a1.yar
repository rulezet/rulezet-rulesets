rule TTP_XOR_WriteProcessMemory_b6a1 {
  strings:
    $key_b6a1 = { e1 d3 [2] d3 f1 [2] d5 c4 [2] fb c4 [2] c4 d8 }

  condition:
    any of them
}