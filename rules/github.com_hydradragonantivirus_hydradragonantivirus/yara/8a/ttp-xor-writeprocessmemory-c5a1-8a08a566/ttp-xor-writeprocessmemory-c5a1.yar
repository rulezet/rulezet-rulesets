rule TTP_XOR_WriteProcessMemory_c5a1 {
  strings:
    $key_c5a1 = { 92 d3 [2] a0 f1 [2] a6 c4 [2] 88 c4 [2] b7 d8 }

  condition:
    any of them
}