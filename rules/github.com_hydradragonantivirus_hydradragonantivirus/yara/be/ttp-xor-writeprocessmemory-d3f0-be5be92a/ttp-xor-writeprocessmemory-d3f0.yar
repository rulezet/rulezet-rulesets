rule TTP_XOR_WriteProcessMemory_d3f0 {
  strings:
    $key_d3f0 = { 84 82 [2] b6 a0 [2] b0 95 [2] 9e 95 [2] a1 89 }

  condition:
    any of them
}