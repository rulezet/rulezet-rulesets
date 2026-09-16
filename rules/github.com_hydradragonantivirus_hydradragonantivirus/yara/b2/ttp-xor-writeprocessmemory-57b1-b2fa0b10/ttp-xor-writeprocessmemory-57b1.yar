rule TTP_XOR_WriteProcessMemory_57b1 {
  strings:
    $key_57b1 = { 00 c3 [2] 32 e1 [2] 34 d4 [2] 1a d4 [2] 25 c8 }

  condition:
    any of them
}