rule TTP_XOR_WriteProcessMemory_c5d6 {
  strings:
    $key_c5d6 = { 92 a4 [2] a0 86 [2] a6 b3 [2] 88 b3 [2] b7 af }

  condition:
    any of them
}