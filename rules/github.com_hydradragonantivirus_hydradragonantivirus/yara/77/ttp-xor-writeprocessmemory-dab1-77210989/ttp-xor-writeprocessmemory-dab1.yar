rule TTP_XOR_WriteProcessMemory_dab1 {
  strings:
    $key_dab1 = { 8d c3 [2] bf e1 [2] b9 d4 [2] 97 d4 [2] a8 c8 }

  condition:
    any of them
}