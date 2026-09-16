rule TTP_XOR_WriteProcessMemory_f2c7 {
  strings:
    $key_f2c7 = { a5 b5 [2] 97 97 [2] 91 a2 [2] bf a2 [2] 80 be }

  condition:
    any of them
}