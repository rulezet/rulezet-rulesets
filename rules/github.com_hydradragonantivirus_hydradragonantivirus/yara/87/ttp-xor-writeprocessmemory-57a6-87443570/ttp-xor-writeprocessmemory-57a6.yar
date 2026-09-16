rule TTP_XOR_WriteProcessMemory_57a6 {
  strings:
    $key_57a6 = { 00 d4 [2] 32 f6 [2] 34 c3 [2] 1a c3 [2] 25 df }

  condition:
    any of them
}