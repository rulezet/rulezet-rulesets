rule TTP_XOR_WriteProcessMemory_f7f8 {
  strings:
    $key_f7f8 = { a0 8a [2] 92 a8 [2] 94 9d [2] ba 9d [2] 85 81 }

  condition:
    any of them
}