rule TTP_XOR_WriteProcessMemory_f110 {
  strings:
    $key_f110 = { a6 62 [2] 94 40 [2] 92 75 [2] bc 75 [2] 83 69 }

  condition:
    any of them
}