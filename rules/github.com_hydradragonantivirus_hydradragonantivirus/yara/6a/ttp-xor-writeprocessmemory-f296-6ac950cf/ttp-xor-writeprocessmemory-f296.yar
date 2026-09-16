rule TTP_XOR_WriteProcessMemory_f296 {
  strings:
    $key_f296 = { a5 e4 [2] 97 c6 [2] 91 f3 [2] bf f3 [2] 80 ef }

  condition:
    any of them
}