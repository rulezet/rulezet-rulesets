rule TTP_XOR_WriteProcessMemory_c2b4 {
  strings:
    $key_c2b4 = { 95 c6 [2] a7 e4 [2] a1 d1 [2] 8f d1 [2] b0 cd }

  condition:
    any of them
}