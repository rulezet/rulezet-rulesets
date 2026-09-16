rule TTP_XOR_WriteProcessMemory_d3a4 {
  strings:
    $key_d3a4 = { 84 d6 [2] b6 f4 [2] b0 c1 [2] 9e c1 [2] a1 dd }

  condition:
    any of them
}