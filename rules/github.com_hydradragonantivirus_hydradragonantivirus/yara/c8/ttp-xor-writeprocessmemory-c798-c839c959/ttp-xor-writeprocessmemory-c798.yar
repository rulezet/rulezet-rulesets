rule TTP_XOR_WriteProcessMemory_c798 {
  strings:
    $key_c798 = { 90 ea [2] a2 c8 [2] a4 fd [2] 8a fd [2] b5 e1 }

  condition:
    any of them
}