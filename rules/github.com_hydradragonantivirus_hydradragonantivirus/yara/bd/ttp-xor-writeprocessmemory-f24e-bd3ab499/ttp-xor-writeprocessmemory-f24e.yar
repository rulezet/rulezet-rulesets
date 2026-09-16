rule TTP_XOR_WriteProcessMemory_f24e {
  strings:
    $key_f24e = { a5 3c [2] 97 1e [2] 91 2b [2] bf 2b [2] 80 37 }

  condition:
    any of them
}