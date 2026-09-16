rule TTP_XOR_WriteProcessMemory_c3c2 {
  strings:
    $key_c3c2 = { 94 b0 [2] a6 92 [2] a0 a7 [2] 8e a7 [2] b1 bb }

  condition:
    any of them
}