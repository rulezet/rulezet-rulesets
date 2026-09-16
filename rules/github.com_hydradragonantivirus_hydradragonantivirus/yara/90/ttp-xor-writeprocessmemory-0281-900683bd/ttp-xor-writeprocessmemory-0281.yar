rule TTP_XOR_WriteProcessMemory_0281 {
  strings:
    $key_0281 = { 55 f3 [2] 67 d1 [2] 61 e4 [2] 4f e4 [2] 70 f8 }

  condition:
    any of them
}