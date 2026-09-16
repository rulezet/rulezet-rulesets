rule TTP_XOR_WriteProcessMemory_a38f {
  strings:
    $key_a38f = { f4 fd [2] c6 df [2] c0 ea [2] ee ea [2] d1 f6 }

  condition:
    any of them
}