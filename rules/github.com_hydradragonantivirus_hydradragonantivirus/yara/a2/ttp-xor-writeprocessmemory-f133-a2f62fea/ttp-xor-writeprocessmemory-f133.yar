rule TTP_XOR_WriteProcessMemory_f133 {
  strings:
    $key_f133 = { a6 41 [2] 94 63 [2] 92 56 [2] bc 56 [2] 83 4a }

  condition:
    any of them
}