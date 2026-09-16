rule TTP_XOR_WriteProcessMemory_c6a0 {
  strings:
    $key_c6a0 = { 91 d2 [2] a3 f0 [2] a5 c5 [2] 8b c5 [2] b4 d9 }

  condition:
    any of them
}