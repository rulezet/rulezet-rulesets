rule TTP_XOR_WriteProcessMemory_d3a0 {
  strings:
    $key_d3a0 = { 84 d2 [2] b6 f0 [2] b0 c5 [2] 9e c5 [2] a1 d9 }

  condition:
    any of them
}