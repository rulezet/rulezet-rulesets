rule TTP_XOR_WriteProcessMemory_0081 {
  strings:
    $key_0081 = { 57 f3 [2] 65 d1 [2] 63 e4 [2] 4d e4 [2] 72 f8 }

  condition:
    any of them
}