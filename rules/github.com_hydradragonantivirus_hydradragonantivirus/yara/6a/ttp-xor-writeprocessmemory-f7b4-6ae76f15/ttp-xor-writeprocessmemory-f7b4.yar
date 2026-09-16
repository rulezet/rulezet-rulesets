rule TTP_XOR_WriteProcessMemory_f7b4 {
  strings:
    $key_f7b4 = { a0 c6 [2] 92 e4 [2] 94 d1 [2] ba d1 [2] 85 cd }

  condition:
    any of them
}