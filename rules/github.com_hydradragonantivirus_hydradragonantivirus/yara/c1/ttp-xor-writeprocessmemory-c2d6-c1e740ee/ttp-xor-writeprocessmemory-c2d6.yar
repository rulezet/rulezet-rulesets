rule TTP_XOR_WriteProcessMemory_c2d6 {
  strings:
    $key_c2d6 = { 95 a4 [2] a7 86 [2] a1 b3 [2] 8f b3 [2] b0 af }

  condition:
    any of them
}