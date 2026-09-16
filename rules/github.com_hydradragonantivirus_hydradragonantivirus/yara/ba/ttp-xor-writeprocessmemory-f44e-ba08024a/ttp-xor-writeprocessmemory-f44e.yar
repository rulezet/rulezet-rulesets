rule TTP_XOR_WriteProcessMemory_f44e {
  strings:
    $key_f44e = { a3 3c [2] 91 1e [2] 97 2b [2] b9 2b [2] 86 37 }

  condition:
    any of them
}