rule TTP_XOR_WriteProcessMemory_d380 {
  strings:
    $key_d380 = { 84 f2 [2] b6 d0 [2] b0 e5 [2] 9e e5 [2] a1 f9 }

  condition:
    any of them
}