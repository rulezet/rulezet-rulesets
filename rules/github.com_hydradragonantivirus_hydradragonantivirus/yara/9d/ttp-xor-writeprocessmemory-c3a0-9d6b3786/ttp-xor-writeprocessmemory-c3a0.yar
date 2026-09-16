rule TTP_XOR_WriteProcessMemory_c3a0 {
  strings:
    $key_c3a0 = { 94 d2 [2] a6 f0 [2] a0 c5 [2] 8e c5 [2] b1 d9 }

  condition:
    any of them
}