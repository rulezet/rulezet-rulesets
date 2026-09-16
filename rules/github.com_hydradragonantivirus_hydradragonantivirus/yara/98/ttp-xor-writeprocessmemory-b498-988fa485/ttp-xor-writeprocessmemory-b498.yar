rule TTP_XOR_WriteProcessMemory_b498 {
  strings:
    $key_b498 = { e3 ea [2] d1 c8 [2] d7 fd [2] f9 fd [2] c6 e1 }

  condition:
    any of them
}