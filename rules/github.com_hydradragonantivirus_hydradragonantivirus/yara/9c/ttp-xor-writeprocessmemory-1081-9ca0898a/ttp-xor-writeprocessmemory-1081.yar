rule TTP_XOR_WriteProcessMemory_1081 {
  strings:
    $key_1081 = { 47 f3 [2] 75 d1 [2] 73 e4 [2] 5d e4 [2] 62 f8 }

  condition:
    any of them
}