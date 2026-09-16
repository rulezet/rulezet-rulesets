rule TTP_XOR_WriteProcessMemory_5990 {
  strings:
    $key_5990 = { 0e e2 [2] 3c c0 [2] 3a f5 [2] 14 f5 [2] 2b e9 }

  condition:
    any of them
}