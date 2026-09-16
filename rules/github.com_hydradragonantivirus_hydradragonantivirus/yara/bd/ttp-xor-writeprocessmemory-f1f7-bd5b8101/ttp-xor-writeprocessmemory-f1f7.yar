rule TTP_XOR_WriteProcessMemory_f1f7 {
  strings:
    $key_f1f7 = { a6 85 [2] 94 a7 [2] 92 92 [2] bc 92 [2] 83 8e }

  condition:
    any of them
}