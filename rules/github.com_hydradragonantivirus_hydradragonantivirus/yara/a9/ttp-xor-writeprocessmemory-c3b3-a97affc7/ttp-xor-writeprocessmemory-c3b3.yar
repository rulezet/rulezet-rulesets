rule TTP_XOR_WriteProcessMemory_c3b3 {
  strings:
    $key_c3b3 = { 94 c1 [2] a6 e3 [2] a0 d6 [2] 8e d6 [2] b1 ca }

  condition:
    any of them
}