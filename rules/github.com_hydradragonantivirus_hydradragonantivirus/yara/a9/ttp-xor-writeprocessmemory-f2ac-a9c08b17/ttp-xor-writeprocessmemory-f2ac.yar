rule TTP_XOR_WriteProcessMemory_f2ac {
  strings:
    $key_f2ac = { a5 de [2] 97 fc [2] 91 c9 [2] bf c9 [2] 80 d5 }

  condition:
    any of them
}