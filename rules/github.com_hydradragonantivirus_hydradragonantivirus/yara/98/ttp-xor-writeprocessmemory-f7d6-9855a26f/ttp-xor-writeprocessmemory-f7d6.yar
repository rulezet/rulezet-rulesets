rule TTP_XOR_WriteProcessMemory_f7d6 {
  strings:
    $key_f7d6 = { a0 a4 [2] 92 86 [2] 94 b3 [2] ba b3 [2] 85 af }

  condition:
    any of them
}