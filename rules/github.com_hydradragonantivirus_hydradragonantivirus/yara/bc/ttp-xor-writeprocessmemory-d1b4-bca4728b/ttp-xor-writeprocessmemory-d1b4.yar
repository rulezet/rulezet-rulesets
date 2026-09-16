rule TTP_XOR_WriteProcessMemory_d1b4 {
  strings:
    $key_d1b4 = { 86 c6 [2] b4 e4 [2] b2 d1 [2] 9c d1 [2] a3 cd }

  condition:
    any of them
}