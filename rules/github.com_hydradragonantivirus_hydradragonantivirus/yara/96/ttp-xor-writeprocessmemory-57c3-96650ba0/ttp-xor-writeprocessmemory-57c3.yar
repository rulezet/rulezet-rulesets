rule TTP_XOR_WriteProcessMemory_57c3 {
  strings:
    $key_57c3 = { 00 b1 [2] 32 93 [2] 34 a6 [2] 1a a6 [2] 25 ba }

  condition:
    any of them
}