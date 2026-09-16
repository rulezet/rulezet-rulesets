rule TTP_XOR_WriteProcessMemory_c1b4 {
  strings:
    $key_c1b4 = { 96 c6 [2] a4 e4 [2] a2 d1 [2] 8c d1 [2] b3 cd }

  condition:
    any of them
}