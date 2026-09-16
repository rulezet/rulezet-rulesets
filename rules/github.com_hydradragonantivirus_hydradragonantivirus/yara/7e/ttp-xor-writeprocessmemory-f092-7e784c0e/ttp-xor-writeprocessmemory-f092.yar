rule TTP_XOR_WriteProcessMemory_f092 {
  strings:
    $key_f092 = { a7 e0 [2] 95 c2 [2] 93 f7 [2] bd f7 [2] 82 eb }

  condition:
    any of them
}