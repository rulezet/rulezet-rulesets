rule TTP_XOR_WriteProcessMemory_d3e0 {
  strings:
    $key_d3e0 = { 84 92 [2] b6 b0 [2] b0 85 [2] 9e 85 [2] a1 99 }

  condition:
    any of them
}