rule TTP_XOR_WriteProcessMemory_b78f {
  strings:
    $key_b78f = { e0 fd [2] d2 df [2] d4 ea [2] fa ea [2] c5 f6 }

  condition:
    any of them
}