rule TTP_XOR_WriteProcessMemory_c5c1 {
  strings:
    $key_c5c1 = { 92 b3 [2] a0 91 [2] a6 a4 [2] 88 a4 [2] b7 b8 }

  condition:
    any of them
}