rule TTP_XOR_WriteProcessMemory_5481 {
  strings:
    $key_5481 = { 03 f3 [2] 31 d1 [2] 37 e4 [2] 19 e4 [2] 26 f8 }

  condition:
    any of them
}