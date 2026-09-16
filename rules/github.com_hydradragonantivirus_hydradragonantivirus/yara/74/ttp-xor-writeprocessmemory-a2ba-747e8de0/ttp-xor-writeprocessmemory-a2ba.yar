rule TTP_XOR_WriteProcessMemory_a2ba {
  strings:
    $key_a2ba = { f5 c8 [2] c7 ea [2] c1 df [2] ef df [2] d0 c3 }

  condition:
    any of them
}