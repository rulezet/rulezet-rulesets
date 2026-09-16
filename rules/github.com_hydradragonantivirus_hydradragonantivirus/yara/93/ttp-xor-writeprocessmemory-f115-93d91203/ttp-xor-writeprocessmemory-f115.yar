rule TTP_XOR_WriteProcessMemory_f115 {
  strings:
    $key_f115 = { a6 67 [2] 94 45 [2] 92 70 [2] bc 70 [2] 83 6c }

  condition:
    any of them
}