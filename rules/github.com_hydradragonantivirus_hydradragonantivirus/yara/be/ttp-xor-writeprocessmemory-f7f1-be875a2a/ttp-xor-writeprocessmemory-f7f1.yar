rule TTP_XOR_WriteProcessMemory_f7f1 {
  strings:
    $key_f7f1 = { a0 83 [2] 92 a1 [2] 94 94 [2] ba 94 [2] 85 88 }

  condition:
    any of them
}