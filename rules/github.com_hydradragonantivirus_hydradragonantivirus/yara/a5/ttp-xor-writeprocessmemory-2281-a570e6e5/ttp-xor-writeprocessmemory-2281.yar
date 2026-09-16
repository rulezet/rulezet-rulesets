rule TTP_XOR_WriteProcessMemory_2281 {
  strings:
    $key_2281 = { 75 f3 [2] 47 d1 [2] 41 e4 [2] 6f e4 [2] 50 f8 }

  condition:
    any of them
}