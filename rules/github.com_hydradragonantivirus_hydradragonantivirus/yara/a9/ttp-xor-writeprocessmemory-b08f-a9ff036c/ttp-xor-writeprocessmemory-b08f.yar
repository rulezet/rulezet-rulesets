rule TTP_XOR_WriteProcessMemory_b08f {
  strings:
    $key_b08f = { e7 fd [2] d5 df [2] d3 ea [2] fd ea [2] c2 f6 }

  condition:
    any of them
}