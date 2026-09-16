rule TTP_XOR_WriteProcessMemory_f12e {
  strings:
    $key_f12e = { a6 5c [2] 94 7e [2] 92 4b [2] bc 4b [2] 83 57 }

  condition:
    any of them
}