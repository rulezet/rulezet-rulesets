rule TTP_XOR_WriteProcessMemory_c1d4 {
  strings:
    $key_c1d4 = { 96 a6 [2] a4 84 [2] a2 b1 [2] 8c b1 [2] b3 ad }

  condition:
    any of them
}