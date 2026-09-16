rule TTP_XOR_WriteProcessMemory_f20b {
  strings:
    $key_f20b = { a5 79 [2] 97 5b [2] 91 6e [2] bf 6e [2] 80 72 }

  condition:
    any of them
}