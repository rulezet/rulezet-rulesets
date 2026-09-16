rule TTP_XOR_WriteProcessMemory_3498 {
  strings:
    $key_3498 = { 63 ea [2] 51 c8 [2] 57 fd [2] 79 fd [2] 46 e1 }

  condition:
    any of them
}