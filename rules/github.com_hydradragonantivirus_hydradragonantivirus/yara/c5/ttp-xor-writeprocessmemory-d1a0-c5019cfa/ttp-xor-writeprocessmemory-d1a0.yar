rule TTP_XOR_WriteProcessMemory_d1a0 {
  strings:
    $key_d1a0 = { 86 d2 [2] b4 f0 [2] b2 c5 [2] 9c c5 [2] a3 d9 }

  condition:
    any of them
}