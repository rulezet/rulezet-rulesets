rule TTP_XOR_WriteProcessMemory_d4c2 {
  strings:
    $key_d4c2 = { 83 b0 [2] b1 92 [2] b7 a7 [2] 99 a7 [2] a6 bb }

  condition:
    any of them
}