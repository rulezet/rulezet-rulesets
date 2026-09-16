rule TTP_XOR_WriteProcessMemory_4681 {
  strings:
    $key_4681 = { 11 f3 [2] 23 d1 [2] 25 e4 [2] 0b e4 [2] 34 f8 }

  condition:
    any of them
}