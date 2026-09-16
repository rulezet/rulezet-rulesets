rule TTP_XOR_WriteProcessMemory_57e7 {
  strings:
    $key_57e7 = { 00 95 [2] 32 b7 [2] 34 82 [2] 1a 82 [2] 25 9e }

  condition:
    any of them
}