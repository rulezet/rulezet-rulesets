rule TTP_XOR_WriteProcessMemory_5390 {
  strings:
    $key_5390 = { 04 e2 [2] 36 c0 [2] 30 f5 [2] 1e f5 [2] 21 e9 }

  condition:
    any of them
}