rule TTP_XOR_WriteProcessMemory_d391 {
  strings:
    $key_d391 = { 84 e3 [2] b6 c1 [2] b0 f4 [2] 9e f4 [2] a1 e8 }

  condition:
    any of them
}