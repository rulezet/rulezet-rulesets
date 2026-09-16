rule TTP_XOR_WriteProcessMemory_d3b0 {
  strings:
    $key_d3b0 = { 84 c2 [2] b6 e0 [2] b0 d5 [2] 9e d5 [2] a1 c9 }

  condition:
    any of them
}