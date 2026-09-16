rule TTP_XOR_WriteProcessMemory_b691 {
  strings:
    $key_b691 = { e1 e3 [2] d3 c1 [2] d5 f4 [2] fb f4 [2] c4 e8 }

  condition:
    any of them
}