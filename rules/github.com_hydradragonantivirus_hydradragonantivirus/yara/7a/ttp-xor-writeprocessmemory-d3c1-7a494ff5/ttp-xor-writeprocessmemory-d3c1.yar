rule TTP_XOR_WriteProcessMemory_d3c1 {
  strings:
    $key_d3c1 = { 84 b3 [2] b6 91 [2] b0 a4 [2] 9e a4 [2] a1 b8 }

  condition:
    any of them
}