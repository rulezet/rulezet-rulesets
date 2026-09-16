rule TTP_XOR_WriteProcessMemory_c0b4 {
  strings:
    $key_c0b4 = { 97 c6 [2] a5 e4 [2] a3 d1 [2] 8d d1 [2] b2 cd }

  condition:
    any of them
}