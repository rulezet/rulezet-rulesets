rule TTP_XOR_WriteProcessMemory_f255 {
  strings:
    $key_f255 = { a5 27 [2] 97 05 [2] 91 30 [2] bf 30 [2] 80 2c }

  condition:
    any of them
}