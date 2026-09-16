rule TTP_XOR_WriteProcessMemory_c580 {
  strings:
    $key_c580 = { 92 f2 [2] a0 d0 [2] a6 e5 [2] 88 e5 [2] b7 f9 }

  condition:
    any of them
}