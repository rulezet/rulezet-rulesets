rule TTP_XOR_WriteProcessMemory_57b0 {
  strings:
    $key_57b0 = { 00 c2 [2] 32 e0 [2] 34 d5 [2] 1a d5 [2] 25 c9 }

  condition:
    any of them
}