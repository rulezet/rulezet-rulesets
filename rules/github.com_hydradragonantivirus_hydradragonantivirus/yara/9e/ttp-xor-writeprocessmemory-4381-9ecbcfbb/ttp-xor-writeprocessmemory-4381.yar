rule TTP_XOR_WriteProcessMemory_4381 {
  strings:
    $key_4381 = { 14 f3 [2] 26 d1 [2] 20 e4 [2] 0e e4 [2] 31 f8 }

  condition:
    any of them
}