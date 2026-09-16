rule TTP_XOR_WriteProcessMemory_57a0 {
  strings:
    $key_57a0 = { 00 d2 [2] 32 f0 [2] 34 c5 [2] 1a c5 [2] 25 d9 }

  condition:
    any of them
}