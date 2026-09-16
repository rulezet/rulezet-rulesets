rule TTP_XOR_WriteProcessMemory_f7f5 {
  strings:
    $key_f7f5 = { a0 87 [2] 92 a5 [2] 94 90 [2] ba 90 [2] 85 8c }

  condition:
    any of them
}