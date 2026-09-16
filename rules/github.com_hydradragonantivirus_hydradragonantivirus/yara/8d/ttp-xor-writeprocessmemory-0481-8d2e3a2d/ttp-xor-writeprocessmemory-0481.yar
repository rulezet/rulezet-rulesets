rule TTP_XOR_WriteProcessMemory_0481 {
  strings:
    $key_0481 = { 53 f3 [2] 61 d1 [2] 67 e4 [2] 49 e4 [2] 76 f8 }

  condition:
    any of them
}