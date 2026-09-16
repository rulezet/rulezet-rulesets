rule TTP_XOR_WriteProcessMemory_7381 {
  strings:
    $key_7381 = { 24 f3 [2] 16 d1 [2] 10 e4 [2] 3e e4 [2] 01 f8 }

  condition:
    any of them
}