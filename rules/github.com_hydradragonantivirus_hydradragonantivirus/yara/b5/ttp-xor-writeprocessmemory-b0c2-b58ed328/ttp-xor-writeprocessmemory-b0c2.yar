rule TTP_XOR_WriteProcessMemory_b0c2 {
  strings:
    $key_b0c2 = { e7 b0 [2] d5 92 [2] d3 a7 [2] fd a7 [2] c2 bb }

  condition:
    any of them
}