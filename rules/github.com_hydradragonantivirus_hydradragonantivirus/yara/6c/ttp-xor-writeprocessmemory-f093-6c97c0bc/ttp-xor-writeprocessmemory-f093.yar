rule TTP_XOR_WriteProcessMemory_f093 {
  strings:
    $key_f093 = { a7 e1 [2] 95 c3 [2] 93 f6 [2] bd f6 [2] 82 ea }

  condition:
    any of them
}