rule TTP_XOR_WriteProcessMemory_f178 {
  strings:
    $key_f178 = { a6 0a [2] 94 28 [2] 92 1d [2] bc 1d [2] 83 01 }

  condition:
    any of them
}