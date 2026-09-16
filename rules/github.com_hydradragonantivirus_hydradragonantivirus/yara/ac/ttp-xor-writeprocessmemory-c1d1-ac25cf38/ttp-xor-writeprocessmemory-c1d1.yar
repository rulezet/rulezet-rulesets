rule TTP_XOR_WriteProcessMemory_c1d1 {
  strings:
    $key_c1d1 = { 96 a3 [2] a4 81 [2] a2 b4 [2] 8c b4 [2] b3 a8 }

  condition:
    any of them
}