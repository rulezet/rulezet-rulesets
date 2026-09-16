rule TTP_XOR_WriteProcessMemory_f7d0 {
  strings:
    $key_f7d0 = { a0 a2 [2] 92 80 [2] 94 b5 [2] ba b5 [2] 85 a9 }

  condition:
    any of them
}