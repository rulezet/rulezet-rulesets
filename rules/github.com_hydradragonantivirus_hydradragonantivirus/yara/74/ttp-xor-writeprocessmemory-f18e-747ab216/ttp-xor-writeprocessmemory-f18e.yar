rule TTP_XOR_WriteProcessMemory_f18e {
  strings:
    $key_f18e = { a6 fc [2] 94 de [2] 92 eb [2] bc eb [2] 83 f7 }

  condition:
    any of them
}