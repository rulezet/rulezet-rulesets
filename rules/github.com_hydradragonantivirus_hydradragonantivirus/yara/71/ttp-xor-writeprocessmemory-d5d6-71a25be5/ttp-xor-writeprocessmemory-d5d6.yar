rule TTP_XOR_WriteProcessMemory_d5d6 {
  strings:
    $key_d5d6 = { 82 a4 [2] b0 86 [2] b6 b3 [2] 98 b3 [2] a7 af }

  condition:
    any of them
}