rule TTP_XOR_WriteProcessMemory_c7d6 {
  strings:
    $key_c7d6 = { 90 a4 [2] a2 86 [2] a4 b3 [2] 8a b3 [2] b5 af }

  condition:
    any of them
}