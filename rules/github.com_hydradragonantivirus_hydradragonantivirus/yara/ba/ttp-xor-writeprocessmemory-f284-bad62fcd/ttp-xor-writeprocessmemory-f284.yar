rule TTP_XOR_WriteProcessMemory_f284 {
  strings:
    $key_f284 = { a5 f6 [2] 97 d4 [2] 91 e1 [2] bf e1 [2] 80 fd }

  condition:
    any of them
}