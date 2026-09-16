rule TTP_XOR_WriteProcessMemory_f2c2 {
  strings:
    $key_f2c2 = { a5 b0 [2] 97 92 [2] 91 a7 [2] bf a7 [2] 80 bb }

  condition:
    any of them
}