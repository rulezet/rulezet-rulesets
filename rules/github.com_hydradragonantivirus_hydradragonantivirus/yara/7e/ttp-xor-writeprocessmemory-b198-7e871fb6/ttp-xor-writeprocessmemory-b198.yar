rule TTP_XOR_WriteProcessMemory_b198 {
  strings:
    $key_b198 = { e6 ea [2] d4 c8 [2] d2 fd [2] fc fd [2] c3 e1 }

  condition:
    any of them
}