rule TTP_XOR_WriteProcessMemory_7398 {
  strings:
    $key_7398 = { 24 ea [2] 16 c8 [2] 10 fd [2] 3e fd [2] 01 e1 }

  condition:
    any of them
}