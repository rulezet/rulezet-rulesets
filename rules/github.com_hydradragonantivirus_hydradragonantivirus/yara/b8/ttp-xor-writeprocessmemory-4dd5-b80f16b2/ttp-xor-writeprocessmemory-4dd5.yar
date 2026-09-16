rule TTP_XOR_WriteProcessMemory_4dd5 {
  strings:
    $key_4dd5 = { 1a a7 [2] 28 85 [2] 2e b0 [2] 00 b0 [2] 3f ac }

  condition:
    any of them
}