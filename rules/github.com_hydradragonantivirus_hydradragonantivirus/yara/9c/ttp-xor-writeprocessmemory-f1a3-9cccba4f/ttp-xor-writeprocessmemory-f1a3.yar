rule TTP_XOR_WriteProcessMemory_f1a3 {
  strings:
    $key_f1a3 = { a6 d1 [2] 94 f3 [2] 92 c6 [2] bc c6 [2] 83 da }

  condition:
    any of them
}