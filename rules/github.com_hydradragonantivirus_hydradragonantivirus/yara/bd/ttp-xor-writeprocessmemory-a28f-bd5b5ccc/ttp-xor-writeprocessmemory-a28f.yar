rule TTP_XOR_WriteProcessMemory_a28f {
  strings:
    $key_a28f = { f5 fd [2] c7 df [2] c1 ea [2] ef ea [2] d0 f6 }

  condition:
    any of them
}