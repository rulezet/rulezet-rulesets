rule TTP_XOR_WriteProcessMemory_f091 {
  strings:
    $key_f091 = { a7 e3 [2] 95 c1 [2] 93 f4 [2] bd f4 [2] 82 e8 }

  condition:
    any of them
}