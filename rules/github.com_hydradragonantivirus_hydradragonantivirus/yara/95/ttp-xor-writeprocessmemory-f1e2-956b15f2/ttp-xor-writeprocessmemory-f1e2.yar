rule TTP_XOR_WriteProcessMemory_f1e2 {
  strings:
    $key_f1e2 = { a6 90 [2] 94 b2 [2] 92 87 [2] bc 87 [2] 83 9b }

  condition:
    any of them
}