rule TTP_XOR_WriteProcessMemory_7598 {
  strings:
    $key_7598 = { 22 ea [2] 10 c8 [2] 16 fd [2] 38 fd [2] 07 e1 }

  condition:
    any of them
}