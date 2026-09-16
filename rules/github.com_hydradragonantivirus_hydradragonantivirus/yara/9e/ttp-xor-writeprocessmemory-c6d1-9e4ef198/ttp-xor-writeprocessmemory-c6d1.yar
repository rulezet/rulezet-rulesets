rule TTP_XOR_WriteProcessMemory_c6d1 {
  strings:
    $key_c6d1 = { 91 a3 [2] a3 81 [2] a5 b4 [2] 8b b4 [2] b4 a8 }

  condition:
    any of them
}