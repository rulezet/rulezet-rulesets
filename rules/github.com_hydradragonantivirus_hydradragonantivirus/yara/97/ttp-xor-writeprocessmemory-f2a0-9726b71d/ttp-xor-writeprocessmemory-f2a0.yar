rule TTP_XOR_WriteProcessMemory_f2a0 {
  strings:
    $key_f2a0 = { a5 d2 [2] 97 f0 [2] 91 c5 [2] bf c5 [2] 80 d9 }

  condition:
    any of them
}