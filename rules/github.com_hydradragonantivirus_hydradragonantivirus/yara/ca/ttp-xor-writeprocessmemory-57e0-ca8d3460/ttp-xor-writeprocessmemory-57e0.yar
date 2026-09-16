rule TTP_XOR_WriteProcessMemory_57e0 {
  strings:
    $key_57e0 = { 00 92 [2] 32 b0 [2] 34 85 [2] 1a 85 [2] 25 99 }

  condition:
    any of them
}