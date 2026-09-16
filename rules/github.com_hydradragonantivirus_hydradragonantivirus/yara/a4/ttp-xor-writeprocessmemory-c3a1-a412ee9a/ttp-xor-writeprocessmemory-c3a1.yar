rule TTP_XOR_WriteProcessMemory_c3a1 {
  strings:
    $key_c3a1 = { 94 d3 [2] a6 f1 [2] a0 c4 [2] 8e c4 [2] b1 d8 }

  condition:
    any of them
}