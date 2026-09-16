rule TTP_XOR_WriteProcessMemory_d2b4 {
  strings:
    $key_d2b4 = { 85 c6 [2] b7 e4 [2] b1 d1 [2] 9f d1 [2] a0 cd }

  condition:
    any of them
}