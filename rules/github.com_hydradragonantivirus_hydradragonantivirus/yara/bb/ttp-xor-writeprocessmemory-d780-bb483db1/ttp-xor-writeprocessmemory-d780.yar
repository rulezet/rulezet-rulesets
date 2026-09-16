rule TTP_XOR_WriteProcessMemory_d780 {
  strings:
    $key_d780 = { 80 f2 [2] b2 d0 [2] b4 e5 [2] 9a e5 [2] a5 f9 }

  condition:
    any of them
}