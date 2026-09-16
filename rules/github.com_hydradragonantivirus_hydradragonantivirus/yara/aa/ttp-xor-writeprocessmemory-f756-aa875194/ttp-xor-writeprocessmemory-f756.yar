rule TTP_XOR_WriteProcessMemory_f756 {
  strings:
    $key_f756 = { a0 24 [2] 92 06 [2] 94 33 [2] ba 33 [2] 85 2f }

  condition:
    any of them
}