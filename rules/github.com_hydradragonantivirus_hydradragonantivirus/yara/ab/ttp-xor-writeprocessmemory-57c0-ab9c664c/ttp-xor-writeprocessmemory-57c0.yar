rule TTP_XOR_WriteProcessMemory_57c0 {
  strings:
    $key_57c0 = { 00 b2 [2] 32 90 [2] 34 a5 [2] 1a a5 [2] 25 b9 }

  condition:
    any of them
}