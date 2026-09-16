rule TTP_XOR_WriteProcessMemory_c298 {
  strings:
    $key_c298 = { 95 ea [2] a7 c8 [2] a1 fd [2] 8f fd [2] b0 e1 }

  condition:
    any of them
}