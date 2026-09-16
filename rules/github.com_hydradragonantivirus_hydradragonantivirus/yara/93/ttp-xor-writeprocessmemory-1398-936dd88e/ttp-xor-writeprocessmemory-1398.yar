rule TTP_XOR_WriteProcessMemory_1398 {
  strings:
    $key_1398 = { 44 ea [2] 76 c8 [2] 70 fd [2] 5e fd [2] 61 e1 }

  condition:
    any of them
}