rule TTP_XOR_WriteProcessMemory_4081 {
  strings:
    $key_4081 = { 17 f3 [2] 25 d1 [2] 23 e4 [2] 0d e4 [2] 32 f8 }

  condition:
    any of them
}