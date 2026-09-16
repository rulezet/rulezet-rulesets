rule TTP_XOR_WriteProcessMemory_1481 {
  strings:
    $key_1481 = { 43 f3 [2] 71 d1 [2] 77 e4 [2] 59 e4 [2] 66 f8 }

  condition:
    any of them
}