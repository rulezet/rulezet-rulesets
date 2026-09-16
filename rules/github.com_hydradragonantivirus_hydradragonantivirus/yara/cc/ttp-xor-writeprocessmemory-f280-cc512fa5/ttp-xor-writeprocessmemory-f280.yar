rule TTP_XOR_WriteProcessMemory_f280 {
  strings:
    $key_f280 = { a5 f2 [2] 97 d0 [2] 91 e5 [2] bf e5 [2] 80 f9 }

  condition:
    any of them
}