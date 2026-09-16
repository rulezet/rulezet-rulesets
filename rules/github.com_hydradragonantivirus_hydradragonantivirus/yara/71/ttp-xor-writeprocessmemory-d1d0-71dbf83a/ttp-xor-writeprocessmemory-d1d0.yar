rule TTP_XOR_WriteProcessMemory_d1d0 {
  strings:
    $key_d1d0 = { 86 a2 [2] b4 80 [2] b2 b5 [2] 9c b5 [2] a3 a9 }

  condition:
    any of them
}