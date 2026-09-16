rule TTP_XOR_WriteProcessMemory_f722 {
  strings:
    $key_f722 = { a0 50 [2] 92 72 [2] 94 47 [2] ba 47 [2] 85 5b }

  condition:
    any of them
}