rule TTP_XOR_WriteProcessMemory_63f6 {
  strings:
    $key_63f6 = { 34 84 [2] 06 a6 [2] 00 93 [2] 2e 93 [2] 11 8f }

  condition:
    any of them
}