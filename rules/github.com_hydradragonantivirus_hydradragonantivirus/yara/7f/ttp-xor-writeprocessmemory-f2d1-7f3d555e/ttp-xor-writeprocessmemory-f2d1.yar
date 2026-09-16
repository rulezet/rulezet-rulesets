rule TTP_XOR_WriteProcessMemory_f2d1 {
  strings:
    $key_f2d1 = { a5 a3 [2] 97 81 [2] 91 b4 [2] bf b4 [2] 80 a8 }

  condition:
    any of them
}