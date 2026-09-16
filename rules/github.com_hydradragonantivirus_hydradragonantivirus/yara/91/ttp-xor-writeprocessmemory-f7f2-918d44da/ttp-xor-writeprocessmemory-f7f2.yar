rule TTP_XOR_WriteProcessMemory_f7f2 {
  strings:
    $key_f7f2 = { a0 80 [2] 92 a2 [2] 94 97 [2] ba 97 [2] 85 8b }

  condition:
    any of them
}