rule TTP_XOR_WriteProcessMemory_f111 {
  strings:
    $key_f111 = { a6 63 [2] 94 41 [2] 92 74 [2] bc 74 [2] 83 68 }

  condition:
    any of them
}