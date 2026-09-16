rule TTP_XOR_WriteProcessMemory_f1f2 {
  strings:
    $key_f1f2 = { a6 80 [2] 94 a2 [2] 92 97 [2] bc 97 [2] 83 8b }

  condition:
    any of them
}