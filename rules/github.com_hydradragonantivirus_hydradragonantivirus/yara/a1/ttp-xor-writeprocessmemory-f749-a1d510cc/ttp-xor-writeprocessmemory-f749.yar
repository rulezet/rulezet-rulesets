rule TTP_XOR_WriteProcessMemory_f749 {
  strings:
    $key_f749 = { a0 3b [2] 92 19 [2] 94 2c [2] ba 2c [2] 85 30 }

  condition:
    any of them
}