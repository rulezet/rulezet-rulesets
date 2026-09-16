rule TTP_XOR_WriteProcessMemory_d7b0 {
  strings:
    $key_d7b0 = { 80 c2 [2] b2 e0 [2] b4 d5 [2] 9a d5 [2] a5 c9 }

  condition:
    any of them
}