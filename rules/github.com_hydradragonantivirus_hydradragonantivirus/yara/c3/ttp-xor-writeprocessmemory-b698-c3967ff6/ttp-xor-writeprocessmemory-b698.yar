rule TTP_XOR_WriteProcessMemory_b698 {
  strings:
    $key_b698 = { e1 ea [2] d3 c8 [2] d5 fd [2] fb fd [2] c4 e1 }

  condition:
    any of them
}