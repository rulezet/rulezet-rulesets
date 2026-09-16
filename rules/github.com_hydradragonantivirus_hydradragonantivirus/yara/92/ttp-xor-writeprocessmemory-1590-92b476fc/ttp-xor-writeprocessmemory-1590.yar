rule TTP_XOR_WriteProcessMemory_1590 {
  strings:
    $key_1590 = { 42 e2 [2] 70 c0 [2] 76 f5 [2] 58 f5 [2] 67 e9 }

  condition:
    any of them
}