rule TTP_XOR_WriteProcessMemory_57e2 {
  strings:
    $key_57e2 = { 00 90 [2] 32 b2 [2] 34 87 [2] 1a 87 [2] 25 9b }

  condition:
    any of them
}