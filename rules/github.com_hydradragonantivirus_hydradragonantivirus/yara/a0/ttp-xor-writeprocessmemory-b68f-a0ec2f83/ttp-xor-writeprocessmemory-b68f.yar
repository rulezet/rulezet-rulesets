rule TTP_XOR_WriteProcessMemory_b68f {
  strings:
    $key_b68f = { e1 fd [2] d3 df [2] d5 ea [2] fb ea [2] c4 f6 }

  condition:
    any of them
}