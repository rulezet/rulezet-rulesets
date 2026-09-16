rule TTP_XOR_WriteProcessMemory_f10b {
  strings:
    $key_f10b = { a6 79 [2] 94 5b [2] 92 6e [2] bc 6e [2] 83 72 }

  condition:
    any of them
}