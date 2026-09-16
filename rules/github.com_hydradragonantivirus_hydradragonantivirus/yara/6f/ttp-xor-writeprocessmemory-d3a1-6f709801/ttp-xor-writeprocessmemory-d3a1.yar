rule TTP_XOR_WriteProcessMemory_d3a1 {
  strings:
    $key_d3a1 = { 84 d3 [2] b6 f1 [2] b0 c4 [2] 9e c4 [2] a1 d8 }

  condition:
    any of them
}