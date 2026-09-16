rule TTP_XOR_WriteProcessMemory_c1d6 {
  strings:
    $key_c1d6 = { 96 a4 [2] a4 86 [2] a2 b3 [2] 8c b3 [2] b3 af }

  condition:
    any of them
}