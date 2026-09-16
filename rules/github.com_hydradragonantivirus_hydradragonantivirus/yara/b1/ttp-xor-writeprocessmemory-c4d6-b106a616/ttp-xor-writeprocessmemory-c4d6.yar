rule TTP_XOR_WriteProcessMemory_c4d6 {
  strings:
    $key_c4d6 = { 93 a4 [2] a1 86 [2] a7 b3 [2] 89 b3 [2] b6 af }

  condition:
    any of them
}