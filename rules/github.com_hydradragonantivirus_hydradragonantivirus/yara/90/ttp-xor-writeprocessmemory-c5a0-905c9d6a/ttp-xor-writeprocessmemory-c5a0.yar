rule TTP_XOR_WriteProcessMemory_c5a0 {
  strings:
    $key_c5a0 = { 92 d2 [2] a0 f0 [2] a6 c5 [2] 88 c5 [2] b7 d9 }

  condition:
    any of them
}