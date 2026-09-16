rule TTP_XOR_WriteProcessMemory_1281 {
  strings:
    $key_1281 = { 45 f3 [2] 77 d1 [2] 71 e4 [2] 5f e4 [2] 60 f8 }

  condition:
    any of them
}