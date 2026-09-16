rule TTP_XOR_WriteProcessMemory_f1d0 {
  strings:
    $key_f1d0 = { a6 a2 [2] 94 80 [2] 92 b5 [2] bc b5 [2] 83 a9 }

  condition:
    any of them
}