rule TTP_XOR_WriteProcessMemory_4598 {
  strings:
    $key_4598 = { 12 ea [2] 20 c8 [2] 26 fd [2] 08 fd [2] 37 e1 }

  condition:
    any of them
}