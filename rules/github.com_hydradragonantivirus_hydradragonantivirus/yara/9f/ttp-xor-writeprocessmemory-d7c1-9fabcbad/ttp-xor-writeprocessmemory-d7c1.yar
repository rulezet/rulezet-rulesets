rule TTP_XOR_WriteProcessMemory_d7c1 {
  strings:
    $key_d7c1 = { 80 b3 [2] b2 91 [2] b4 a4 [2] 9a a4 [2] a5 b8 }

  condition:
    any of them
}