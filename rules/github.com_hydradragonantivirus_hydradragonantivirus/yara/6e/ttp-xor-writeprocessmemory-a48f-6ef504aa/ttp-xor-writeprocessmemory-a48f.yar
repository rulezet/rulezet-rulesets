rule TTP_XOR_WriteProcessMemory_a48f {
  strings:
    $key_a48f = { f3 fd [2] c1 df [2] c7 ea [2] e9 ea [2] d6 f6 }

  condition:
    any of them
}