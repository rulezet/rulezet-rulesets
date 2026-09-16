rule TTP_XOR_WriteProcessMemory_b48f {
  strings:
    $key_b48f = { e3 fd [2] d1 df [2] d7 ea [2] f9 ea [2] c6 f6 }

  condition:
    any of them
}