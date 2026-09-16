rule TTP_XOR_WriteProcessMemory_5298 {
  strings:
    $key_5298 = { 05 ea [2] 37 c8 [2] 31 fd [2] 1f fd [2] 20 e1 }

  condition:
    any of them
}