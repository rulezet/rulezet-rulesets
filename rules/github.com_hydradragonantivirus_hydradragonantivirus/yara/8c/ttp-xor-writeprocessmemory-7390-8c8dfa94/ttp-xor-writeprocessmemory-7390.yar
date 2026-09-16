rule TTP_XOR_WriteProcessMemory_7390 {
  strings:
    $key_7390 = { 24 e2 [2] 16 c0 [2] 10 f5 [2] 3e f5 [2] 01 e9 }

  condition:
    any of them
}