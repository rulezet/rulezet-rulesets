rule TTP_XOR_WriteProcessMemory_c4b4 {
  strings:
    $key_c4b4 = { 93 c6 [2] a1 e4 [2] a7 d1 [2] 89 d1 [2] b6 cd }

  condition:
    any of them
}