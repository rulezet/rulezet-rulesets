rule TTP_XOR_WriteProcessMemory_d3c0 {
  strings:
    $key_d3c0 = { 84 b2 [2] b6 90 [2] b0 a5 [2] 9e a5 [2] a1 b9 }

  condition:
    any of them
}