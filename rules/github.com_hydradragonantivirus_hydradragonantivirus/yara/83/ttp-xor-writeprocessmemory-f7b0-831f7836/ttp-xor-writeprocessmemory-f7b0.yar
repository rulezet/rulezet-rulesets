rule TTP_XOR_WriteProcessMemory_f7b0 {
  strings:
    $key_f7b0 = { a0 c2 [2] 92 e0 [2] 94 d5 [2] ba d5 [2] 85 c9 }

  condition:
    any of them
}