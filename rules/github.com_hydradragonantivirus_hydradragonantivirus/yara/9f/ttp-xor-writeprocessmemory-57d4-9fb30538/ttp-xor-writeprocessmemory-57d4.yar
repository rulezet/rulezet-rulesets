rule TTP_XOR_WriteProcessMemory_57d4 {
  strings:
    $key_57d4 = { 00 a6 [2] 32 84 [2] 34 b1 [2] 1a b1 [2] 25 ad }

  condition:
    any of them
}