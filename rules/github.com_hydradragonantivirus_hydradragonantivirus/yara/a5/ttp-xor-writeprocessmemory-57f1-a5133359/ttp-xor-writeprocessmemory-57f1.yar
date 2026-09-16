rule TTP_XOR_WriteProcessMemory_57f1 {
  strings:
    $key_57f1 = { 00 83 [2] 32 a1 [2] 34 94 [2] 1a 94 [2] 25 88 }

  condition:
    any of them
}