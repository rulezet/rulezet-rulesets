rule TTP_XOR_WriteProcessMemory_a08f {
  strings:
    $key_a08f = { f7 fd [2] c5 df [2] c3 ea [2] ed ea [2] d2 f6 }

  condition:
    any of them
}