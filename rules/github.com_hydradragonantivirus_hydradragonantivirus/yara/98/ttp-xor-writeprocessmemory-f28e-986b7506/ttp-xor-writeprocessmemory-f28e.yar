rule TTP_XOR_WriteProcessMemory_f28e {
  strings:
    $key_f28e = { a5 fc [2] 97 de [2] 91 eb [2] bf eb [2] 80 f7 }

  condition:
    any of them
}