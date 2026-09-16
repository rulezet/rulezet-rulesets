rule TTP_XOR_WriteProcessMemory_c0c2 {
  strings:
    $key_c0c2 = { 97 b0 [2] a5 92 [2] a3 a7 [2] 8d a7 [2] b2 bb }

  condition:
    any of them
}