rule TTP_XOR_WriteProcessMemory_2381 {
  strings:
    $key_2381 = { 74 f3 [2] 46 d1 [2] 40 e4 [2] 6e e4 [2] 51 f8 }

  condition:
    any of them
}