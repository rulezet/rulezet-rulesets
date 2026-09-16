rule TTP_XOR_WriteProcessMemory_c6d4 {
  strings:
    $key_c6d4 = { 91 a6 [2] a3 84 [2] a5 b1 [2] 8b b1 [2] b4 ad }

  condition:
    any of them
}