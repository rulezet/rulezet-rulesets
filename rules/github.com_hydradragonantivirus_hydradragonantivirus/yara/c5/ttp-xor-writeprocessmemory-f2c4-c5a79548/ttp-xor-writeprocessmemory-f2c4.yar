rule TTP_XOR_WriteProcessMemory_f2c4 {
  strings:
    $key_f2c4 = { a5 b6 [2] 97 94 [2] 91 a1 [2] bf a1 [2] 80 bd }

  condition:
    any of them
}