rule TTP_XOR_WriteProcessMemory_a0ba {
  strings:
    $key_a0ba = { f7 c8 [2] c5 ea [2] c3 df [2] ed df [2] d2 c3 }

  condition:
    any of them
}