rule TTP_XOR_WriteProcessMemory_3481 {
  strings:
    $key_3481 = { 63 f3 [2] 51 d1 [2] 57 e4 [2] 79 e4 [2] 46 f8 }

  condition:
    any of them
}