rule TTP_XOR_WriteProcessMemory_f142 {
  strings:
    $key_f142 = { a6 30 [2] 94 12 [2] 92 27 [2] bc 27 [2] 83 3b }

  condition:
    any of them
}