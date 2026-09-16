rule TTP_XOR_WriteProcessMemory_f2c0 {
  strings:
    $key_f2c0 = { a5 b2 [2] 97 90 [2] 91 a5 [2] bf a5 [2] 80 b9 }

  condition:
    any of them
}