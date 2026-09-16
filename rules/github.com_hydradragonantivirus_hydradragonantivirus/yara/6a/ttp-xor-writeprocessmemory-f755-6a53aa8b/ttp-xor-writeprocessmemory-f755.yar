rule TTP_XOR_WriteProcessMemory_f755 {
  strings:
    $key_f755 = { a0 27 [2] 92 05 [2] 94 30 [2] ba 30 [2] 85 2c }

  condition:
    any of them
}