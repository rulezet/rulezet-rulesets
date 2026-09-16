rule TTP_XOR_WriteProcessMemory_c4c1 {
  strings:
    $key_c4c1 = { 93 b3 [2] a1 91 [2] a7 a4 [2] 89 a4 [2] b6 b8 }

  condition:
    any of them
}