rule TTP_XOR_WriteProcessMemory_c1a0 {
  strings:
    $key_c1a0 = { 96 d2 [2] a4 f0 [2] a2 c5 [2] 8c c5 [2] b3 d9 }

  condition:
    any of them
}