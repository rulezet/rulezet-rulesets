rule TTP_XOR_WriteProcessMemory_2798 {
  strings:
    $key_2798 = { 70 ea [2] 42 c8 [2] 44 fd [2] 6a fd [2] 55 e1 }

  condition:
    any of them
}