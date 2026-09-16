rule TTP_XOR_WriteProcessMemory_f126 {
  strings:
    $key_f126 = { a6 54 [2] 94 76 [2] 92 43 [2] bc 43 [2] 83 5f }

  condition:
    any of them
}