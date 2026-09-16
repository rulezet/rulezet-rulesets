rule TTP_XOR_WriteProcessMemory_f12b {
  strings:
    $key_f12b = { a6 59 [2] 94 7b [2] 92 4e [2] bc 4e [2] 83 52 }

  condition:
    any of them
}