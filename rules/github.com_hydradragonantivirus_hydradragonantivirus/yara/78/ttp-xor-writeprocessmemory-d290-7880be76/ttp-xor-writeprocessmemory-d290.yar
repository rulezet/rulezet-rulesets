rule TTP_XOR_WriteProcessMemory_d290 {
  strings:
    $key_d290 = { 85 e2 [2] b7 c0 [2] b1 f5 [2] 9f f5 [2] a0 e9 }

  condition:
    any of them
}