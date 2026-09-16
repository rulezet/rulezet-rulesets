rule TTP_XOR_WriteProcessMemory_f1f1 {
  strings:
    $key_f1f1 = { a6 83 [2] 94 a1 [2] 92 94 [2] bc 94 [2] 83 88 }

  condition:
    any of them
}