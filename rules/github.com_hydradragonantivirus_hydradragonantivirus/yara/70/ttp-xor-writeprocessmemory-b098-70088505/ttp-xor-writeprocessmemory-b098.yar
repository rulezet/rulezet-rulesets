rule TTP_XOR_WriteProcessMemory_b098 {
  strings:
    $key_b098 = { e7 ea [2] d5 c8 [2] d3 fd [2] fd fd [2] c2 e1 }

  condition:
    any of them
}