rule TTP_XOR_WriteProcessMemory_c3a5 {
  strings:
    $key_c3a5 = { 94 d7 [2] a6 f5 [2] a0 c0 [2] 8e c0 [2] b1 dc }

  condition:
    any of them
}