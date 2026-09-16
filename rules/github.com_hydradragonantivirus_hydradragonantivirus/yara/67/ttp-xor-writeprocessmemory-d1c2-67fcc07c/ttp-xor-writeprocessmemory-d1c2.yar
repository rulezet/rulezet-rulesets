rule TTP_XOR_WriteProcessMemory_d1c2 {
  strings:
    $key_d1c2 = { 86 b0 [2] b4 92 [2] b2 a7 [2] 9c a7 [2] a3 bb }

  condition:
    any of them
}