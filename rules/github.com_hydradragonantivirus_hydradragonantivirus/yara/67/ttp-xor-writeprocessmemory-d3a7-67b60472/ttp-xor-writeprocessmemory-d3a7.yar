rule TTP_XOR_WriteProcessMemory_d3a7 {
  strings:
    $key_d3a7 = { 84 d5 [2] b6 f7 [2] b0 c2 [2] 9e c2 [2] a1 de }

  condition:
    any of them
}