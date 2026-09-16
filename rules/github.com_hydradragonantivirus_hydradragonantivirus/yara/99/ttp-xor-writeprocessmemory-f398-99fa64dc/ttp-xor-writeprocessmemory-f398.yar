rule TTP_XOR_WriteProcessMemory_f398 {
  strings:
    $key_f398 = { a4 ea [2] 96 c8 [2] 90 fd [2] be fd [2] 81 e1 }

  condition:
    any of them
}