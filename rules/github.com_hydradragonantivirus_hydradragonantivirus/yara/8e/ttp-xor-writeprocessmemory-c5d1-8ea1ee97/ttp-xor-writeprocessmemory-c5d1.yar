rule TTP_XOR_WriteProcessMemory_c5d1 {
  strings:
    $key_c5d1 = { 92 a3 [2] a0 81 [2] a6 b4 [2] 88 b4 [2] b7 a8 }

  condition:
    any of them
}