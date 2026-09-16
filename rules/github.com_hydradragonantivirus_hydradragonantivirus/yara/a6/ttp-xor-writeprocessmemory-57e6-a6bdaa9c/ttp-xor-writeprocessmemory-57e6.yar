rule TTP_XOR_WriteProcessMemory_57e6 {
  strings:
    $key_57e6 = { 00 94 [2] 32 b6 [2] 34 83 [2] 1a 83 [2] 25 9f }

  condition:
    any of them
}