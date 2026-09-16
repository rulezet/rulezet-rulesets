rule TTP_XOR_WriteProcessMemory_4390 {
  strings:
    $key_4390 = { 14 e2 [2] 26 c0 [2] 20 f5 [2] 0e f5 [2] 31 e9 }

  condition:
    any of them
}