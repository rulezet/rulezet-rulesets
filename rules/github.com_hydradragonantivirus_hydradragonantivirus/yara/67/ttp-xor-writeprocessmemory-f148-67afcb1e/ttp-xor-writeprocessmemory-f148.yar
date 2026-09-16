rule TTP_XOR_WriteProcessMemory_f148 {
  strings:
    $key_f148 = { a6 3a [2] 94 18 [2] 92 2d [2] bc 2d [2] 83 31 }

  condition:
    any of them
}