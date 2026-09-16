rule TTP_XOR_WriteProcessMemory_57e1 {
  strings:
    $key_57e1 = { 00 93 [2] 32 b1 [2] 34 84 [2] 1a 84 [2] 25 98 }

  condition:
    any of them
}