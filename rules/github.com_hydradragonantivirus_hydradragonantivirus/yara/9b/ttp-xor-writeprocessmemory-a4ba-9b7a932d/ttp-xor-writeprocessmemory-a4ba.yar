rule TTP_XOR_WriteProcessMemory_a4ba {
  strings:
    $key_a4ba = { f3 c8 [2] c1 ea [2] c7 df [2] e9 df [2] d6 c3 }

  condition:
    any of them
}