rule TTP_XOR_WriteProcessMemory_c1d0 {
  strings:
    $key_c1d0 = { 96 a2 [2] a4 80 [2] a2 b5 [2] 8c b5 [2] b3 a9 }

  condition:
    any of them
}