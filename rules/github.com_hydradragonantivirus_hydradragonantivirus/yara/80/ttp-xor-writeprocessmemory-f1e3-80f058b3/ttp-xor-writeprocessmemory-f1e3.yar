rule TTP_XOR_WriteProcessMemory_f1e3 {
  strings:
    $key_f1e3 = { a6 91 [2] 94 b3 [2] 92 86 [2] bc 86 [2] 83 9a }

  condition:
    any of them
}