rule TTP_XOR_WriteProcessMemory_c4b1 {
  strings:
    $key_c4b1 = { 93 c3 [2] a1 e1 [2] a7 d4 [2] 89 d4 [2] b6 c8 }

  condition:
    any of them
}