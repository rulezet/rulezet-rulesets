rule TTP_XOR_WriteProcessMemory_d6b1 {
  strings:
    $key_d6b1 = { 81 c3 [2] b3 e1 [2] b5 d4 [2] 9b d4 [2] a4 c8 }

  condition:
    any of them
}