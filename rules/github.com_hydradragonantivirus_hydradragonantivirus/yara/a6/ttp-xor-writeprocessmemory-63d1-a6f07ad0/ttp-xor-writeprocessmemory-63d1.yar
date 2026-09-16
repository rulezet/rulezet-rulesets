rule TTP_XOR_WriteProcessMemory_63d1 {
  strings:
    $key_63d1 = { 34 a3 [2] 06 81 [2] 00 b4 [2] 2e b4 [2] 11 a8 }

  condition:
    any of them
}