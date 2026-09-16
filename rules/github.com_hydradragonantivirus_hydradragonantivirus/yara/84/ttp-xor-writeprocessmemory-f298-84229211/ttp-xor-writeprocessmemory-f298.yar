rule TTP_XOR_WriteProcessMemory_f298 {
  strings:
    $key_f298 = { a5 ea [2] 97 c8 [2] 91 fd [2] bf fd [2] 80 e1 }

  condition:
    any of them
}