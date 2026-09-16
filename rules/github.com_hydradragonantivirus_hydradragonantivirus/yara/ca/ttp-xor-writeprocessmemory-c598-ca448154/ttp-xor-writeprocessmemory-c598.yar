rule TTP_XOR_WriteProcessMemory_c598 {
  strings:
    $key_c598 = { 92 ea [2] a0 c8 [2] a6 fd [2] 88 fd [2] b7 e1 }

  condition:
    any of them
}