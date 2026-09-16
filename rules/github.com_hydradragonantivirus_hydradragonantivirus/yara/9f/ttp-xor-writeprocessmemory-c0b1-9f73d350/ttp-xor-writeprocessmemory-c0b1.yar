rule TTP_XOR_WriteProcessMemory_c0b1 {
  strings:
    $key_c0b1 = { 97 c3 [2] a5 e1 [2] a3 d4 [2] 8d d4 [2] b2 c8 }

  condition:
    any of them
}