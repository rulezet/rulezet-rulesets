rule TTP_XOR_WriteProcessMemory_57a5 {
  strings:
    $key_57a5 = { 00 d7 [2] 32 f5 [2] 34 c0 [2] 1a c0 [2] 25 dc }

  condition:
    any of them
}