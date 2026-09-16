rule TTP_XOR_WriteProcessMemory_b38f {
  strings:
    $key_b38f = { e4 fd [2] d6 df [2] d0 ea [2] fe ea [2] c1 f6 }

  condition:
    any of them
}