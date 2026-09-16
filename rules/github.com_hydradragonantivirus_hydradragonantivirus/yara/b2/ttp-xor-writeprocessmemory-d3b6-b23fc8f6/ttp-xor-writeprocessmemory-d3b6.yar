rule TTP_XOR_WriteProcessMemory_d3b6 {
  strings:
    $key_d3b6 = { 84 c4 [2] b6 e6 [2] b0 d3 [2] 9e d3 [2] a1 cf }

  condition:
    any of them
}