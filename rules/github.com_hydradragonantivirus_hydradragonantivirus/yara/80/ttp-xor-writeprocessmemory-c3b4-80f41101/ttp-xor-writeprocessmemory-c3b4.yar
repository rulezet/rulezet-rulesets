rule TTP_XOR_WriteProcessMemory_c3b4 {
  strings:
    $key_c3b4 = { 94 c6 [2] a6 e4 [2] a0 d1 [2] 8e d1 [2] b1 cd }

  condition:
    any of them
}