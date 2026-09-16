rule TTP_XOR_WriteProcessMemory_d390 {
  strings:
    $key_d390 = { 84 e2 [2] b6 c0 [2] b0 f5 [2] 9e f5 [2] a1 e9 }

  condition:
    any of them
}