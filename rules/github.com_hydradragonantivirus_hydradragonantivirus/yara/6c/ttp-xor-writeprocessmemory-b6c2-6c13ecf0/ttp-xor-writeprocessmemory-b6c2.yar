rule TTP_XOR_WriteProcessMemory_b6c2 {
  strings:
    $key_b6c2 = { e1 b0 [2] d3 92 [2] d5 a7 [2] fb a7 [2] c4 bb }

  condition:
    any of them
}