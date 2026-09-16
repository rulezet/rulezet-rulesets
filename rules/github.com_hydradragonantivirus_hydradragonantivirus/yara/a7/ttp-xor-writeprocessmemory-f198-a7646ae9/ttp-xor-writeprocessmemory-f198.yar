rule TTP_XOR_WriteProcessMemory_f198 {
  strings:
    $key_f198 = { a6 ea [2] 94 c8 [2] 92 fd [2] bc fd [2] 83 e1 }

  condition:
    any of them
}