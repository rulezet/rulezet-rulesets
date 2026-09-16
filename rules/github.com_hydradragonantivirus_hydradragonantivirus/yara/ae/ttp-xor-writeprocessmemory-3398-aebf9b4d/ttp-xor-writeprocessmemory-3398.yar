rule TTP_XOR_WriteProcessMemory_3398 {
  strings:
    $key_3398 = { 64 ea [2] 56 c8 [2] 50 fd [2] 7e fd [2] 41 e1 }

  condition:
    any of them
}