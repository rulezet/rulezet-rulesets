rule TTP_XOR_WriteProcessMemory_b6a3 {
  strings:
    $key_b6a3 = { e1 d1 [2] d3 f3 [2] d5 c6 [2] fb c6 [2] c4 da }

  condition:
    any of them
}