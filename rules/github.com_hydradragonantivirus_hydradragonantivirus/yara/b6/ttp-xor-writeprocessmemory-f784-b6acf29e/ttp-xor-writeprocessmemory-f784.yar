rule TTP_XOR_WriteProcessMemory_f784 {
  strings:
    $key_f784 = { a0 f6 [2] 92 d4 [2] 94 e1 [2] ba e1 [2] 85 fd }

  condition:
    any of them
}