rule TTP_XOR_WriteProcessMemory_c1c0 {
  strings:
    $key_c1c0 = { 96 b2 [2] a4 90 [2] a2 a5 [2] 8c a5 [2] b3 b9 }

  condition:
    any of them
}