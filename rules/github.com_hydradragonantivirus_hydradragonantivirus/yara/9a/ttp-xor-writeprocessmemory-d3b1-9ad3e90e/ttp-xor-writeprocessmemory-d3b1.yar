rule TTP_XOR_WriteProcessMemory_d3b1 {
  strings:
    $key_d3b1 = { 84 c3 [2] b6 e1 [2] b0 d4 [2] 9e d4 [2] a1 c8 }

  condition:
    any of them
}