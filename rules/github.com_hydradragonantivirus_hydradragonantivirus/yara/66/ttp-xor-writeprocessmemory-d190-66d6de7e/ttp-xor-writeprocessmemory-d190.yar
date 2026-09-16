rule TTP_XOR_WriteProcessMemory_d190 {
  strings:
    $key_d190 = { 86 e2 [2] b4 c0 [2] b2 f5 [2] 9c f5 [2] a3 e9 }

  condition:
    any of them
}