rule TTP_XOR_WriteProcessMemory_f785 {
  strings:
    $key_f785 = { a0 f7 [2] 92 d5 [2] 94 e0 [2] ba e0 [2] 85 fc }

  condition:
    any of them
}