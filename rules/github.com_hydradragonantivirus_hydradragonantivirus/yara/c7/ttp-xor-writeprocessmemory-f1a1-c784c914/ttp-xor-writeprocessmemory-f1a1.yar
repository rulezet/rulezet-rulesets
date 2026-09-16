rule TTP_XOR_WriteProcessMemory_f1a1 {
  strings:
    $key_f1a1 = { a6 d3 [2] 94 f1 [2] 92 c4 [2] bc c4 [2] 83 d8 }

  condition:
    any of them
}