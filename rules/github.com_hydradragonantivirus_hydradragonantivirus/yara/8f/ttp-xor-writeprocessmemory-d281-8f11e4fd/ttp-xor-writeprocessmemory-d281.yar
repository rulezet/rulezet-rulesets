rule TTP_XOR_WriteProcessMemory_d281 {
  strings:
    $key_d281 = { 85 f3 [2] b7 d1 [2] b1 e4 [2] 9f e4 [2] a0 f8 }

  condition:
    any of them
}