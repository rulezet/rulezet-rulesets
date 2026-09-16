rule TTP_XOR_WriteProcessMemory_a6ba {
  strings:
    $key_a6ba = { f1 c8 [2] c3 ea [2] c5 df [2] eb df [2] d4 c3 }

  condition:
    any of them
}