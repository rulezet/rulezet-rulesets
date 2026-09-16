rule TTP_XOR_WriteProcessMemory_a498 {
  strings:
    $key_a498 = { f3 ea [2] c1 c8 [2] c7 fd [2] e9 fd [2] d6 e1 }

  condition:
    any of them
}