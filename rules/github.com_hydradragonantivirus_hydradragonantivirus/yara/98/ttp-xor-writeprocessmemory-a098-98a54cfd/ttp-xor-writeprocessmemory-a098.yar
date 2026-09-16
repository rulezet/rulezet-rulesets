rule TTP_XOR_WriteProcessMemory_a098 {
  strings:
    $key_a098 = { f7 ea [2] c5 c8 [2] c3 fd [2] ed fd [2] d2 e1 }

  condition:
    any of them
}