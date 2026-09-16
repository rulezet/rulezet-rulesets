rule TTP_XOR_WriteProcessMemory_d280 {
  strings:
    $key_d280 = { 85 f2 [2] b7 d0 [2] b1 e5 [2] 9f e5 [2] a0 f9 }

  condition:
    any of them
}