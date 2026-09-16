rule TTP_XOR_WriteProcessMemory_5281 {
  strings:
    $key_5281 = { 05 f3 [2] 37 d1 [2] 31 e4 [2] 1f e4 [2] 20 f8 }

  condition:
    any of them
}