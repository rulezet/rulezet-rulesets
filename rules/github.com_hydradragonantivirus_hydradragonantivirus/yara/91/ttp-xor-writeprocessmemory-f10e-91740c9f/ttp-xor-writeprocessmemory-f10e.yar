rule TTP_XOR_WriteProcessMemory_f10e {
  strings:
    $key_f10e = { a6 7c [2] 94 5e [2] 92 6b [2] bc 6b [2] 83 77 }

  condition:
    any of them
}