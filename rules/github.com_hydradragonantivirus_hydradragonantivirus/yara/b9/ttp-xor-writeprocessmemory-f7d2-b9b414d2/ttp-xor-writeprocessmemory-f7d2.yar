rule TTP_XOR_WriteProcessMemory_f7d2 {
  strings:
    $key_f7d2 = { a0 a0 [2] 92 82 [2] 94 b7 [2] ba b7 [2] 85 ab }

  condition:
    any of them
}