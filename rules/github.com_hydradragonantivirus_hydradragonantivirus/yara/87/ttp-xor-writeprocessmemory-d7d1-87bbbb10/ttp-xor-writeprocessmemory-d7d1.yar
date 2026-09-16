rule TTP_XOR_WriteProcessMemory_d7d1 {
  strings:
    $key_d7d1 = { 80 a3 [2] b2 81 [2] b4 b4 [2] 9a b4 [2] a5 a8 }

  condition:
    any of them
}