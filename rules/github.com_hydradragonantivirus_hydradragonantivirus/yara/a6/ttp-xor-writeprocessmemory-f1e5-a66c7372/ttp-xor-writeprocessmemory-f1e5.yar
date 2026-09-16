rule TTP_XOR_WriteProcessMemory_f1e5 {
  strings:
    $key_f1e5 = { a6 97 [2] 94 b5 [2] 92 80 [2] bc 80 [2] 83 9c }

  condition:
    any of them
}