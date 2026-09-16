rule TTP_XOR_WriteProcessMemory_f7a7 {
  strings:
    $key_f7a7 = { a0 d5 [2] 92 f7 [2] 94 c2 [2] ba c2 [2] 85 de }

  condition:
    any of them
}