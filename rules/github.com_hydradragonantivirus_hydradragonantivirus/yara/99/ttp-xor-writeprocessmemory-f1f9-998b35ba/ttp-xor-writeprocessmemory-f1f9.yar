rule TTP_XOR_WriteProcessMemory_f1f9 {
  strings:
    $key_f1f9 = { a6 8b [2] 94 a9 [2] 92 9c [2] bc 9c [2] 83 80 }

  condition:
    any of them
}