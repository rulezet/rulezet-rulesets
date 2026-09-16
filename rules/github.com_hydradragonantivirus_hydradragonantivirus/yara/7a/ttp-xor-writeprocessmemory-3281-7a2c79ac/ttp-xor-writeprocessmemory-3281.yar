rule TTP_XOR_WriteProcessMemory_3281 {
  strings:
    $key_3281 = { 65 f3 [2] 57 d1 [2] 51 e4 [2] 7f e4 [2] 40 f8 }

  condition:
    any of them
}