rule TTP_XOR_WriteProcessMemory_f196 {
  strings:
    $key_f196 = { a6 e4 [2] 94 c6 [2] 92 f3 [2] bc f3 [2] 83 ef }

  condition:
    any of them
}