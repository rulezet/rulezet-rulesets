rule TTP_XOR_WriteProcessMemory_2398 {
  strings:
    $key_2398 = { 74 ea [2] 46 c8 [2] 40 fd [2] 6e fd [2] 51 e1 }

  condition:
    any of them
}