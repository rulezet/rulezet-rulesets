rule TTP_XOR_WriteProcessMemory_d4b0 {
  strings:
    $key_d4b0 = { 83 c2 [2] b1 e0 [2] b7 d5 [2] 99 d5 [2] a6 c9 }

  condition:
    any of them
}