rule TTP_XOR_WriteProcessMemory_c784 {
  strings:
    $key_c784 = { 90 f6 [2] a2 d4 [2] a4 e1 [2] 8a e1 [2] b5 fd }

  condition:
    any of them
}