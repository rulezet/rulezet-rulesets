rule TTP_XOR_WriteProcessMemory_c0b0 {
  strings:
    $key_c0b0 = { 97 c2 [2] a5 e0 [2] a3 d5 [2] 8d d5 [2] b2 c9 }

  condition:
    any of them
}