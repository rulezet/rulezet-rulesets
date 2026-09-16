rule TTP_XOR_WriteProcessMemory_f1bb {
  strings:
    $key_f1bb = { a6 c9 [2] 94 eb [2] 92 de [2] bc de [2] 83 c2 }

  condition:
    any of them
}