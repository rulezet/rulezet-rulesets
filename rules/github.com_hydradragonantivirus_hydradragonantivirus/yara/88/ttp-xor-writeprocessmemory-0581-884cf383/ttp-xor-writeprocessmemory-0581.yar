rule TTP_XOR_WriteProcessMemory_0581 {
  strings:
    $key_0581 = { 52 f3 [2] 60 d1 [2] 66 e4 [2] 48 e4 [2] 77 f8 }

  condition:
    any of them
}