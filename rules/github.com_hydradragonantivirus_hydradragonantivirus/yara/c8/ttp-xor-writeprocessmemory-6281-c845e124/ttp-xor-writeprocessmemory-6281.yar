rule TTP_XOR_WriteProcessMemory_6281 {
  strings:
    $key_6281 = { 35 f3 [2] 07 d1 [2] 01 e4 [2] 2f e4 [2] 10 f8 }

  condition:
    any of them
}