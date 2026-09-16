rule TTP_XOR_WriteProcessMemory_f1b4 {
  strings:
    $key_f1b4 = { a6 c6 [2] 94 e4 [2] 92 d1 [2] bc d1 [2] 83 cd }

  condition:
    any of them
}