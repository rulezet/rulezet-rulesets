rule TTP_XOR_WriteProcessMemory_c498 {
  strings:
    $key_c498 = { 93 ea [2] a1 c8 [2] a7 fd [2] 89 fd [2] b6 e1 }

  condition:
    any of them
}