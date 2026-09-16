rule TTP_XOR_WriteProcessMemory_b18f {
  strings:
    $key_b18f = { e6 fd [2] d4 df [2] d2 ea [2] fc ea [2] c3 f6 }

  condition:
    any of them
}