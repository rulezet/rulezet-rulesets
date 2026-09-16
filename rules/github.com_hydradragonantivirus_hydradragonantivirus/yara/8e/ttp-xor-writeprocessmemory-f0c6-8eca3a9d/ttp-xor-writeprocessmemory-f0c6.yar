rule TTP_XOR_WriteProcessMemory_f0c6 {
  strings:
    $key_f0c6 = { a7 b4 [2] 95 96 [2] 93 a3 [2] bd a3 [2] 82 bf }

  condition:
    any of them
}