rule TTP_XOR_WriteProcessMemory_5581 {
  strings:
    $key_5581 = { 02 f3 [2] 30 d1 [2] 36 e4 [2] 18 e4 [2] 27 f8 }

  condition:
    any of them
}