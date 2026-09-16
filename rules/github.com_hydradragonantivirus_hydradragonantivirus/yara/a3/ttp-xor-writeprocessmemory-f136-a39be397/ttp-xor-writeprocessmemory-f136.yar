rule TTP_XOR_WriteProcessMemory_f136 {
  strings:
    $key_f136 = { a6 44 [2] 94 66 [2] 92 53 [2] bc 53 [2] 83 4f }

  condition:
    any of them
}