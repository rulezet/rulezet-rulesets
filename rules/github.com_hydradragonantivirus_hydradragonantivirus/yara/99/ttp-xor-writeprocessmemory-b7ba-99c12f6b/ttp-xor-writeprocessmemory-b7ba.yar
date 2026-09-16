rule TTP_XOR_WriteProcessMemory_b7ba {
  strings:
    $key_b7ba = { e0 c8 [2] d2 ea [2] d4 df [2] fa df [2] c5 c3 }

  condition:
    any of them
}