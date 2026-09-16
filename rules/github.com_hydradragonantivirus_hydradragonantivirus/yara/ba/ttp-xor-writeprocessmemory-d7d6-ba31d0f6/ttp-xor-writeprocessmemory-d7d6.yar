rule TTP_XOR_WriteProcessMemory_d7d6 {
  strings:
    $key_d7d6 = { 80 a4 [2] b2 86 [2] b4 b3 [2] 9a b3 [2] a5 af }

  condition:
    any of them
}