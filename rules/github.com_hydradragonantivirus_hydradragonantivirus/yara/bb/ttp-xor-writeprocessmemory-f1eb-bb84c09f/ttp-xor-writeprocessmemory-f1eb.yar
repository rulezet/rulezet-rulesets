rule TTP_XOR_WriteProcessMemory_f1eb {
  strings:
    $key_f1eb = { a6 99 [2] 94 bb [2] 92 8e [2] bc 8e [2] 83 92 }

  condition:
    any of them
}