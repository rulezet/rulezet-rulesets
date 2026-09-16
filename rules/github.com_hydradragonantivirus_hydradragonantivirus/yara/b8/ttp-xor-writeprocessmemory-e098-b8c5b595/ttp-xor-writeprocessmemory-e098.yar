rule TTP_XOR_WriteProcessMemory_e098 {
  strings:
    $key_e098 = { b7 ea [2] 85 c8 [2] 83 fd [2] ad fd [2] 92 e1 }

  condition:
    any of them
}